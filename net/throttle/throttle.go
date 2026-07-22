// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package throttle

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/deep-rent/nexus/sys/metrics"
	"github.com/deep-rent/nexus/net/router"
)

// Default values applied by [New] for the optional [Config] fields.
const (
	// DefaultRate is the sustained rate, in tokens per second, at which a
	// drained allowance recovers.
	DefaultRate = rate.Limit(1)
	// DefaultBurst is the number of tokens each key may hold.
	DefaultBurst = 60
)

// sweepInterval bounds how often idle buckets are evicted.
const sweepInterval = time.Minute

// Config carries the tunable settings for a [Throttle]. Zero values are
// replaced with the package defaults by [New].
type Config struct {
	// Rate is the sustained rate, in tokens per second, at which a drained
	// allowance recovers. Defaults to [DefaultRate].
	Rate rate.Limit
	// Burst is the number of tokens each key may hold. It caps how many
	// actions can be taken back to back before the rate takes over. Defaults
	// to [DefaultBurst].
	Burst int
	// Key derives the bucket key from a request for [Throttle.Middleware]. It
	// defaults to the remote address of the TCP connection, with the port
	// stripped, so that all connections from one host share a bucket.
	//
	// Deployments behind a trusted reverse proxy or load balancer should
	// override this to read the forwarded client address, for example from
	// the X-Forwarded-For header. Never trust such headers unless an upstream
	// proxy is guaranteed to overwrite them: a spoofed value lets an attacker
	// pick a fresh bucket for every request and bypass limiting entirely.
	//
	// It is only consulted by [Throttle.Middleware]; the keyed methods take
	// the key directly.
	Key func(*http.Request) string
	// Clock overrides the time source. This is primarily useful for
	// deterministic testing. Defaults to [time.Now].
	Clock func() time.Time
	// Name is the value of the "name" tag on the recorded counters,
	// keeping multiple instances apart in a metrics backend. Defaults to
	// the empty string.
	Name string
	// Registry records the [Decisions] and [Penalties] counters. Defaults
	// to [metrics.DefaultRegistry].
	Registry *metrics.Registry
}

// Names of the counters recorded by a [Throttle], tagged with the instance
// name from [Config.Name].
const (
	// Decisions counts AllowN outcomes, split by the "allowed" tag. Note
	// that requests rejected by [Throttle.Middleware] reserve on the
	// buckets directly and do not pass through here; they surface as 429s
	// in the HTTP server metrics instead.
	Decisions = "throttle_decisions_total"
	// Penalties counts Penalize charges.
	Penalties = "throttle_penalties_total"
)

// Throttle is a set of token buckets keyed by opaque strings.
//
// Each key recovers its allowance at the configured rate up to the configured
// burst. Spending a token that is not available fails; charging a penalty
// pushes a bucket into deficit, so further actions stay blocked until it
// recovers. Buckets whose allowance has fully recovered are indistinguishable
// from new ones and are evicted over time to bound memory.
//
// A Throttle is safe for concurrent use.
type Throttle struct {
	rate  rate.Limit
	burst int
	key   func(*http.Request) string
	clock func() time.Time

	allowed   *metrics.Counter // AllowN spends that succeeded
	rejected  *metrics.Counter // AllowN spends that were rate limited
	penalties *metrics.Counter // Penalize charges

	mu      sync.Mutex
	buckets map[string]*rate.Limiter
	swept   time.Time
}

// New assembles a [Throttle] from the given configuration. It panics if the
// resolved rate or burst is not positive.
func New(cfg Config) *Throttle {
	limit := cfg.Rate
	if limit == 0 {
		limit = DefaultRate
	}
	burst := cfg.Burst
	if burst == 0 {
		burst = DefaultBurst
	}

	switch {
	case limit <= 0:
		panic("rate must be positive")
	case burst <= 0:
		panic("burst must be positive")
	}

	key := cfg.Key
	if key == nil {
		key = RemoteAddr
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	reg := cfg.Registry
	if reg == nil {
		reg = metrics.DefaultRegistry
	}
	name := metrics.T("name", cfg.Name)

	return &Throttle{
		rate:  limit,
		burst: burst,
		key:   key,
		clock: clock,
		allowed: reg.Counter(Decisions,
			name, metrics.T("allowed", "true")),
		rejected: reg.Counter(Decisions,
			name, metrics.T("allowed", "false")),
		penalties: reg.Counter(Penalties, name),
		buckets:   make(map[string]*rate.Limiter),
		swept:     clock(),
	}
}

// RemoteAddr derives a key from the remote address of the request's TCP
// connection, stripping the port so that all connections from one host share
// a bucket. It is the default for [Config.Key].
func RemoteAddr(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// limiter returns the bucket for key, creating a full one on first use. It
// opportunistically evicts recovered buckets to bound memory.
func (t *Throttle) limiter(key string, now time.Time) *rate.Limiter {
	t.mu.Lock()
	defer t.mu.Unlock()

	if now.Sub(t.swept) >= sweepInterval {
		t.sweep(now)
	}

	l, ok := t.buckets[key]
	if !ok {
		l = rate.NewLimiter(t.rate, t.burst)
		t.buckets[key] = l
	}
	return l
}

// sweep drops every bucket whose allowance has fully recovered. Such buckets
// are indistinguishable from freshly created ones, so discarding them loses
// no state; buckets still carrying a deficit are retained. The caller must
// hold the mutex.
func (t *Throttle) sweep(now time.Time) {
	for key, l := range t.buckets {
		if l.TokensAt(now) >= float64(t.burst) {
			delete(t.buckets, key)
		}
	}
	t.swept = now
}

// Allow spends a single token from the given key's bucket, reporting whether
// one was available. A false result means the key is currently rate limited.
func (t *Throttle) Allow(key string) bool {
	return t.AllowN(key, 1)
}

// AllowN spends n tokens from the given key's bucket if that many are
// available, reporting whether the spend succeeded. If fewer than n tokens
// are available, nothing is spent and it returns false. A non-positive n
// spends nothing and returns true.
//
// Every call is counted under [Decisions] with an "allowed" tag.
func (t *Throttle) AllowN(key string, n int) bool {
	if n <= 0 {
		return true
	}
	now := t.clock()
	ok := t.limiter(key, now).AllowN(now, n)
	if ok {
		t.allowed.Inc()
	} else {
		t.rejected.Inc()
	}
	return ok
}

// Blocked reports whether the given key has exhausted its allowance, along
// with the duration until the next token is available. It does not spend any
// allowance itself, so it is safe to call before deciding how to respond.
func (t *Throttle) Blocked(key string) (bool, time.Duration) {
	now := t.clock()
	tokens := t.limiter(key, now).TokensAt(now)
	if tokens >= 1 {
		return false, 0
	}
	wait := (1 - tokens) / float64(t.rate)
	return true, time.Duration(wait * float64(time.Second))
}

// Penalize charges tokens extra tokens against the given key, over and above
// any spent by [Throttle.Allow]. Charging a key that is already exhausted
// pushes it further into deficit, extending how long it stays blocked.
//
// Use it to make an unwanted outcome cost more than an ordinary request: a
// failed authentication attempt, an oversized upload, a cache miss that hit
// the origin. A non-positive charge does nothing. A single call charges at
// most Burst tokens, since a bucket cannot be driven more than a full burst
// into deficit at once.
func (t *Throttle) Penalize(key string, tokens int) {
	if tokens <= 0 {
		return
	}
	if tokens > t.burst {
		tokens = t.burst
	}
	now := t.clock()
	t.limiter(key, now).ReserveN(now, tokens)
	t.penalties.Inc()
}

// Reset restores the full allowance of the given key, discarding any deficit
// it had accrued. Use it once a caller has proven legitimate — a correct
// credential, a completed challenge — so that earlier penalties do not hold
// them back.
func (t *Throttle) Reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.buckets, key)
}

// Middleware returns a [router.Middleware] that spends one token per request
// from the bucket of the key derived by [Config.Key], rejecting the request
// with status 429 and a Retry-After header once the bucket is empty.
//
// It is the one-line way to limit a route by client address. Handlers that
// need to charge only failed attempts, or to key by something other than the
// address, should use the keyed methods directly instead.
func (t *Throttle) Middleware() router.Middleware {
	return t.MiddlewareFunc(t.key)
}

// MiddlewareFunc is [Throttle.Middleware] with an explicit key function,
// letting a caller limit by something other than [Config.Key] — a header, a
// route parameter, a namespaced address — while sharing the same buckets as
// its keyed calls. The buckets it spends from are exactly those addressed by
// the string key returns, so a handler can later penalize or inspect the same
// key.
func (t *Throttle) MiddlewareFunc(
	key func(*http.Request) string,
) router.Middleware {
	return router.RateLimitFunc(func(r *http.Request) *rate.Limiter {
		return t.limiter(key(r), t.clock())
	})
}

// RetryAfter writes the Retry-After header on h for the given wait duration,
// rounded up to whole seconds as required by RFC 9110 Section 10.2.3. A
// non-positive duration writes nothing. It pairs with the duration returned
// by [Throttle.Blocked].
func RetryAfter(h http.Header, wait time.Duration) {
	if wait <= 0 {
		return
	}
	sec := int((wait + time.Second - 1) / time.Second)
	h.Set("Retry-After", strconv.Itoa(sec))
}
