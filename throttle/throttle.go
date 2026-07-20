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

// Package throttle provides a per-key token bucket for rate limiting HTTP
// endpoints, together with the router middleware that applies it.
//
// A [Throttle] hands out one [rate.Limiter] per key and evicts the ones that
// have gone idle, so the number of buckets tracks the number of active
// callers rather than growing without bound. Keys are opaque strings, which
// lets a caller throttle by whatever identifies the actor: a network address,
// a client ID, a username, or a one-time code.
//
// Two usage patterns are supported, and they compose:
//
//   - [Throttle.Middleware] charges every request against the bucket of the
//     requesting address, rejecting it with 429 once the bucket is empty.
//   - [Throttle.Blocked], [Throttle.Penalize] and [Throttle.Reset] let a
//     handler charge only the attempts that actually failed, which is the
//     right shape for credential checks: a caller supplying valid
//     credentials is never slowed down.
//
// # Usage
//
// Guard a set of routes by address:
//
//	t := throttle.New(throttle.Config{})
//	r.Handle("POST /login", login, t.Middleware())
//
// Charge only failed attempts, so that a legitimate caller is unaffected:
//
//	key := "user:" + username
//	if blocked, wait := t.Blocked(key); blocked {
//		throttle.RetryAfter(e, wait)
//		return tooManyAttempts()
//	}
//	if !checkPassword(username, password) {
//		t.Penalize(key)
//		return invalidCredentials()
//	}
//	t.Reset(key)
package throttle

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/deep-rent/nexus/router"
)

// Default values applied by [New] for optional [Config]
// fields.
const (
	// DefaultRate is the sustained rate, in tokens per second, at
	// which a drained allowance recovers.
	DefaultRate = rate.Limit(1)
	// DefaultBurst is the number of tokens each key may hold.
	DefaultBurst = 60
	// DefaultPenalty is the number of tokens charged for a failed
	// authentication attempt.
	DefaultPenalty = 10
)

// sweepInterval bounds how often idle buckets are evicted.
const sweepInterval = time.Minute

// scopeAddr namespaces the buckets keyed by network address, so that an
// address can never share a bucket with an identifier a caller derives.
const scopeAddr = "addr:"

// Config carries the tunable settings for a [Throttle]. Zero values
// are replaced with the package defaults by [New].
type Config struct {
	// Rate is the sustained rate, in tokens per second, at which a drained
	// allowance recovers. Defaults to [DefaultRate].
	Rate rate.Limit
	// Burst is the number of tokens each key may hold. It caps how many
	// attempts can be made back to back. Defaults to
	// [DefaultBurst].
	Burst int
	// Penalty is the number of tokens charged for a failed authentication
	// attempt. Larger values lock out brute-force attempts sooner. It must
	// not exceed Burst. Defaults to [DefaultPenalty].
	Penalty int
	// Key derives the network identity of a request for address-based
	// limiting. It defaults to the remote address of the TCP connection,
	// with the port stripped.
	//
	// Deployments behind a trusted reverse proxy or load balancer should
	// override this to read the forwarded client address, for example from
	// the X-Forwarded-For header. Never trust such headers unless an
	// upstream proxy is guaranteed to overwrite them: a spoofed value lets
	// an attacker pick a fresh bucket for every request and bypass
	// address-based limiting entirely.
	Key func(*http.Request) string
	// Clock overrides the time source. This is primarily useful for
	// deterministic testing. Defaults to [time.Now].
	Clock func() time.Time
}

// Throttle applies token-bucket rate limiting to the credential-verifying
// endpoints of a [Server], charging extra for failed attempts so that
// repeated failures back off progressively.
//
// It maintains one bucket per key across two independent axes:
//
//   - Network address. Every request through [Throttle.Middleware] spends a
//     token, which bounds the raw request volume a single client can
//     generate. Failed attempts spend additional tokens.
//   - Credential identity (client ID, username, or device user code).
//     Successful attempts cost nothing, so legitimate high-volume clients
//     are never throttled; only failures spend tokens. This bounds guesses
//     against a single identity regardless of how many addresses they come
//     from.
//
// Once a bucket is empty, further attempts are rejected until it refills,
// and each additional failure pushes the bucket further into deficit,
// extending the lockout. Proving possession of a credential clears its
// bucket; the address bucket is deliberately not cleared, so that an
// attacker holding one valid credential cannot reset the penalty accrued
// while guessing others.
//
// Pass a Throttle via [Config.Throttle]; [Server.Mount] then applies it
// automatically. A nil Throttle disables throttling. Instances are safe for
// concurrent use.
//
// Buckets are held in memory, so limits apply per process: a horizontally
// scaled deployment divides the effective allowance across replicas. This
// complements, but does not replace, volumetric rate limiting at the load
// balancer or reverse proxy.
type Throttle struct {
	rate    rate.Limit
	burst   int
	penalty int
	key     func(*http.Request) string
	clock   func() time.Time

	mu      sync.Mutex
	buckets map[string]*rate.Limiter
	swept   time.Time
}

// NewThrottle assembles a [Throttle] from the given configuration.
//
// It panics if the resulting rate is not positive, if the burst is not
// positive, or if the penalty exceeds the burst (which would reject every
// attempt outright).
func New(cfg Config) *Throttle {
	limit := cfg.Rate
	if limit == 0 {
		limit = DefaultRate
	}
	burst := cfg.Burst
	if burst == 0 {
		burst = DefaultBurst
	}
	penalty := cfg.Penalty
	if penalty == 0 {
		penalty = DefaultPenalty
	}

	switch {
	case limit <= 0:
		panic("oauth: Config.Rate must be positive")
	case burst <= 0:
		panic("oauth: Config.Burst must be positive")
	case penalty > burst:
		panic("oauth: Config.Penalty must not exceed Burst")
	}

	key := cfg.Key
	if key == nil {
		key = RemoteAddr
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}

	return &Throttle{
		rate:    limit,
		burst:   burst,
		penalty: penalty,
		key:     key,
		clock:   clock,
		buckets: make(map[string]*rate.Limiter),
		swept:   clock(),
	}
}

// RemoteAddr derives a throttle key from the remote address of the request's
// TCP connection, stripping the port so that all connections from one host
// share a bucket. It is the default for [Config.Key].
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
// no state; buckets still carrying a penalty are retained. The caller must
// hold the mutex.
func (t *Throttle) sweep(now time.Time) {
	for key, l := range t.buckets {
		if l.TokensAt(now) >= float64(t.burst) {
			delete(t.buckets, key)
		}
	}
	t.swept = now
}

// Blocked reports whether the given key has exhausted its allowance, along
// with the duration until the next attempt is permitted. It does not spend
// any allowance itself.
//
// Keys are opaque strings; use the scope-prefixed keys produced by the
// [Server] or namespace your own to avoid collisions.
func (t *Throttle) Blocked(key string) (bool, time.Duration) {
	now := t.clock()
	tokens := t.limiter(key, now).TokensAt(now)
	if tokens >= 1 {
		return false, 0
	}
	wait := (1 - tokens) / float64(t.rate)
	return true, time.Duration(wait * float64(time.Second))
}

// Penalize charges the configured penalty against the given key, following a
// failed authentication attempt. Charging a key that is already exhausted
// pushes it further into deficit, extending the lockout.
func (t *Throttle) Penalize(key string) {
	now := t.clock()
	t.limiter(key, now).ReserveN(now, t.penalty)
}

// Reset restores the full allowance of the given key. The [Server] calls it
// once a credential has been proven, so that a legitimate user is not held
// back by earlier mistyped attempts.
func (t *Throttle) Reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.buckets, key)
}

// Middleware returns a [router.Middleware] that spends one token per request
// from the bucket of the requesting address, rejecting the request with
// status 429 and a Retry-After header once the bucket is empty.
//
// [Server.Mount] applies it to the credential-verifying endpoints
// automatically. It is exported so that applications can extend the same
// allowance to their own sensitive routes.
func (t *Throttle) Middleware() router.Middleware {
	return router.RateLimitFunc(func(r *http.Request) *rate.Limiter {
		return t.limiter(t.AddrKey(r), t.clock())
	})
}

// addrKey returns the address-scoped bucket key for the given request.
func (t *Throttle) AddrKey(r *http.Request) string {
	return scopeAddr + t.key(r)
}

// RetryAfter writes the Retry-After header for the given wait duration,
// rounded up to whole seconds as required by RFC 9110 Section 10.2.3. A
// non-positive duration writes nothing.
func RetryAfter(e *router.Exchange, wait time.Duration) {
	if wait <= 0 {
		return
	}
	sec := int(math.Ceil(wait.Seconds()))
	e.SetHeader("Retry-After", strconv.Itoa(sec))
}
