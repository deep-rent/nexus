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

package oauth

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

// Default values applied by [NewThrottle] for optional [ThrottleConfig]
// fields.
const (
	// DefaultThrottleRate is the sustained rate, in tokens per second, at
	// which a drained allowance recovers.
	DefaultThrottleRate = rate.Limit(1)
	// DefaultThrottleBurst is the number of tokens each key may hold.
	DefaultThrottleBurst = 60
	// DefaultThrottlePenalty is the number of tokens charged for a failed
	// authentication attempt.
	DefaultThrottlePenalty = 10
)

// sweepInterval bounds how often idle buckets are evicted.
const sweepInterval = time.Minute

// Key namespaces keep the identifier spaces disjoint, so that a client ID
// can never share a bucket with a username or a network address.
const (
	scopeAddr   = "addr:"
	scopeClient = "client:"
	scopeUser   = "user:"
	scopeCode   = "code:"
)

// ThrottleConfig carries the tunable settings for a [Throttle]. Zero values
// are replaced with the package defaults by [NewThrottle].
type ThrottleConfig struct {
	// Rate is the sustained rate, in tokens per second, at which a drained
	// allowance recovers. Defaults to [DefaultThrottleRate].
	Rate rate.Limit
	// Burst is the number of tokens each key may hold. It caps how many
	// attempts can be made back to back. Defaults to
	// [DefaultThrottleBurst].
	Burst int
	// Penalty is the number of tokens charged for a failed authentication
	// attempt. Larger values lock out brute-force attempts sooner. It must
	// not exceed Burst. Defaults to [DefaultThrottlePenalty].
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
func NewThrottle(cfg ThrottleConfig) *Throttle {
	limit := cfg.Rate
	if limit == 0 {
		limit = DefaultThrottleRate
	}
	burst := cfg.Burst
	if burst == 0 {
		burst = DefaultThrottleBurst
	}
	penalty := cfg.Penalty
	if penalty == 0 {
		penalty = DefaultThrottlePenalty
	}

	switch {
	case limit <= 0:
		panic("oauth: ThrottleConfig.Rate must be positive")
	case burst <= 0:
		panic("oauth: ThrottleConfig.Burst must be positive")
	case penalty > burst:
		panic("oauth: ThrottleConfig.Penalty must not exceed Burst")
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
// share a bucket. It is the default for [ThrottleConfig.Key].
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
		return t.limiter(t.addrKey(r), t.clock())
	})
}

// addrKey returns the address-scoped bucket key for the given request.
func (t *Throttle) addrKey(r *http.Request) string {
	return scopeAddr + t.key(r)
}

// tooManyAttempts builds the OAuth-shaped rejection returned once a
// credential-verifying endpoint has exhausted its throttle allowance.
//
// RFC 6749 defines no error code for rate limiting, so the device-flow
// "slow_down" code (RFC 8628 Section 3.5) is reused: its semantics match
// exactly, and clients that do not recognize it still honor the 429 status
// and the accompanying Retry-After header.
func tooManyAttempts() *Error {
	return &Error{
		Status:      http.StatusTooManyRequests,
		Code:        ErrorCodeSlowDown,
		Description: "too many failed attempts",
	}
}

// tooManyRequests is the [router.Error] counterpart of [tooManyAttempts],
// used by the first-party JSON endpoints.
func tooManyRequests() *router.Error {
	return &router.Error{
		Status:      http.StatusTooManyRequests,
		Reason:      router.ReasonRateLimit,
		Description: "Too many failed attempts. Try again later.",
	}
}

// retryAfter writes the Retry-After header for the given wait duration,
// rounded up to whole seconds as required by RFC 9110 Section 10.2.3.
func retryAfter(e *router.Exchange, wait time.Duration) {
	if wait <= 0 {
		return
	}
	sec := int(math.Ceil(wait.Seconds()))
	e.SetHeader("Retry-After", strconv.Itoa(sec))
}
