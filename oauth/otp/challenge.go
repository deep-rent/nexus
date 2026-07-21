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

package otp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/deep-rent/nexus/log"
)

// Default policy values applied by [New] when the corresponding option is not
// given. They match the historical oauth two-factor defaults.
const (
	// DefaultLifetime is the validity period of a challenge.
	DefaultLifetime = 5 * time.Minute
	// DefaultMaxAttempts is the number of failed confirmations after which a
	// challenge is burned.
	DefaultMaxAttempts = 5
	// DefaultMaxResends is the number of times a single challenge may have its
	// code redelivered. A negative value disables resending entirely.
	DefaultMaxResends = 3
)

// Status is the logical result of a [Challenger.Verify] or [Challenger.Resend]
// call. It is distinct from a Go error, which is reserved for storage and
// delivery failures the caller cannot recover from.
type Status int

const (
	// StatusOK indicates the operation succeeded.
	StatusOK Status = iota
	// StatusInvalid indicates the challenge does not exist, belongs to another
	// purpose, has expired, or was burned by too many attempts. The reasons are
	// deliberately collapsed into one status so that callers cannot leak which
	// applies.
	StatusInvalid
	// StatusWrongCode indicates a live challenge whose submitted code did not
	// match. Returned only by [Challenger.Verify].
	StatusWrongCode
	// StatusResendLimit indicates the challenge has already been resent the
	// maximum number of times. Returned only by [Challenger.Resend].
	StatusResendLimit
)

// Outcome carries the result of a verify or resend operation.
type Outcome struct {
	// Status is the logical result.
	Status Status
	// Owner is the reference stored with the challenge. It is set only when
	// [Challenger.Verify] returns [StatusOK].
	Owner string
	// ExpiresIn is the number of seconds until the challenge expires. It is set
	// only when [Challenger.Resend] returns [StatusOK].
	ExpiresIn int64
}

// OK reports whether the outcome represents success.
func (o Outcome) OK() bool { return o.Status == StatusOK }

// Challenge is the persisted state of a pending one-time password. All secrets
// are stored as digests, never in the clear: a stolen store yields no usable
// codes or handles.
type Challenge struct {
	// ID is the digest of the client-facing handle and the storage key.
	ID string
	// Code is the digest of the current one-time password.
	Code string
	// Owner is an opaque reference to whoever the challenge authenticates
	// (e.g. a subject ID). It is returned verbatim on successful verification.
	Owner string
	// Purpose namespaces distinct flows (e.g. "2fa", "verify:email") so that a
	// handle minted for one flow cannot complete another.
	Purpose string
	// MethodID records the [Method] that last delivered the code, so a resend
	// can default to the same channel.
	MethodID string
	// ExpiresAt is the expiry as a Unix timestamp in seconds. A resend does not
	// extend it.
	ExpiresAt int64
	// Attempts is the number of confirmations tried so far.
	Attempts int
	// Resends is the number of times the code has been redelivered.
	Resends int
}

// Store persists pending challenges keyed by [Challenge.ID].
//
// Implementations are expected to be safe for concurrent use and to honor the
// provided context. Delete must be atomic and report whether this call was the
// one that removed the challenge; the engine relies on that to enforce single
// use under concurrent confirmations.
type Store interface {
	// Create persists a new challenge.
	Create(ctx context.Context, c Challenge) error
	// Get returns the challenge with the given ID. found is false when no such
	// challenge exists (including after expiry-driven cleanup); the returned
	// error is reserved for storage failures.
	Get(ctx context.Context, id string) (c Challenge, found bool, err error)
	// Update persists changes to an existing challenge, keyed by its ID.
	Update(ctx context.Context, c Challenge) error
	// Delete removes the challenge with the given ID, reporting whether it
	// existed and was removed by this call.
	Delete(ctx context.Context, id string) (deleted bool, err error)
}

// Challenger runs the lifecycle of one-time password challenges — minting,
// delivering, verifying, and resending them — over a [Store]. It is
// transport-agnostic: it neither speaks HTTP nor throttles, leaving those to
// the caller, which maps the returned [Outcome] onto its own protocol.
//
// A Challenger is safe for concurrent use if its [Store] is.
type Challenger struct {
	store       Store
	length      int
	lifetime    time.Duration
	maxAttempts int
	maxResends  int
	now         func() time.Time
	newHandle   func() (string, error)
	newCode     func(length int) (string, error)
	logger      *slog.Logger
}

// Option configures a [Challenger].
type Option func(*Challenger)

// WithCodeLength sets the number of digits in a generated code. Values below 1
// are ignored. Defaults to [DefaultLength].
func WithCodeLength(n int) Option {
	return func(c *Challenger) {
		if n > 0 {
			c.length = n
		}
	}
}

// WithLifetime sets the validity period of a challenge. Nonpositive values are
// ignored. Defaults to [DefaultLifetime].
func WithLifetime(d time.Duration) Option {
	return func(c *Challenger) {
		if d > 0 {
			c.lifetime = d
		}
	}
}

// WithMaxAttempts sets the number of failed confirmations after which a
// challenge is burned. Values below 1 are ignored. Defaults to
// [DefaultMaxAttempts].
func WithMaxAttempts(n int) Option {
	return func(c *Challenger) {
		if n > 0 {
			c.maxAttempts = n
		}
	}
}

// WithMaxResends sets how many times a challenge's code may be redelivered. A
// negative value disables resending. Defaults to [DefaultMaxResends].
func WithMaxResends(n int) Option {
	return func(c *Challenger) { c.maxResends = n }
}

// WithClock overrides the time source, primarily for testing. A nil function
// is ignored. Defaults to [time.Now].
func WithClock(now func() time.Time) Option {
	return func(c *Challenger) {
		if now != nil {
			c.now = now
		}
	}
}

// WithHandleGenerator overrides the source of client-facing challenge handles.
// A nil function is ignored. The default draws 32 random bytes from
// crypto/rand.
func WithHandleGenerator(fn func() (string, error)) Option {
	return func(c *Challenger) {
		if fn != nil {
			c.newHandle = fn
		}
	}
}

// WithCodeGenerator overrides the source of one-time passwords. A nil function
// is ignored. Defaults to [Generate].
func WithCodeGenerator(fn func(length int) (string, error)) Option {
	return func(c *Challenger) {
		if fn != nil {
			c.newCode = fn
		}
	}
}

// WithLogger injects a structured logger for best-effort cleanup diagnostics.
// A nil logger is ignored. Defaults to [slog.Default].
func WithLogger(logger *slog.Logger) Option {
	return func(c *Challenger) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// New creates a [Challenger] backed by the given [Store]. It panics if store
// is nil, since that is a startup configuration error.
func New(store Store, opts ...Option) *Challenger {
	if store == nil {
		panic("store is required")
	}
	c := &Challenger{
		store:       store,
		length:      DefaultLength,
		lifetime:    DefaultLifetime,
		maxAttempts: DefaultMaxAttempts,
		maxResends:  DefaultMaxResends,
		now:         time.Now,
		newHandle:   randomHandle,
		newCode:     Generate,
		logger:      slog.Default(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Begin mints a challenge for the given purpose and owner, delivers a fresh
// code through the method, and returns the client-facing handle together with
// the number of seconds until the challenge expires.
//
// The handle is the only reference the caller should hand to the client; the
// code travels solely over the method's side channel. If delivery fails, the
// challenge is removed (best-effort; expiry is the backstop) so the next
// attempt starts clean, and the delivery error is returned.
func (c *Challenger) Begin(
	ctx context.Context,
	purpose, owner string,
	m Method,
) (handle string, expiresIn int64, err error) {
	handle, err = c.newHandle()
	if err != nil {
		return "", 0, err
	}
	code, err := c.newCode(c.length)
	if err != nil {
		return "", 0, err
	}

	ch := Challenge{
		ID:        hashValue(handle),
		Code:      hashValue(code),
		Owner:     owner,
		Purpose:   purpose,
		MethodID:  m.ID,
		ExpiresAt: c.now().Add(c.lifetime).Unix(),
	}
	if err := c.store.Create(ctx, ch); err != nil {
		return "", 0, err
	}

	if err := m.Deliver(ctx, code); err != nil {
		c.deleteBestEffort(ctx, ch.ID, "undeliverable challenge")
		return "", 0, err
	}

	return handle, int64(c.lifetime.Seconds()), nil
}

// Verify confirms a challenge against the code the owner received. The purpose
// must match the one the challenge was minted with.
//
// Codes are short enough to guess, so the method is deliberately hostile: each
// attempt is counted and persisted before the comparison (so a crash cannot
// hand out free guesses), the comparison is constant-time, and a correct code
// deletes the challenge atomically — of two racing confirmations, only the one
// that performs the deletion wins. The error return is reserved for storage
// failures; all logical results are conveyed by the [Outcome].
func (c *Challenger) Verify(
	ctx context.Context,
	purpose, handle, code string,
) (Outcome, error) {
	id := hashValue(handle)

	ch, found, err := c.store.Get(ctx, id)
	if err != nil {
		return Outcome{}, err
	}
	if !found || ch.Purpose != purpose || c.expired(ch) {
		return Outcome{Status: StatusInvalid}, nil
	}

	if ch.Attempts >= c.maxAttempts {
		// Burned: delete best-effort; expiry cleans up on failure.
		c.deleteBestEffort(ctx, id, "burned challenge")
		return Outcome{Status: StatusInvalid}, nil
	}

	// Record the attempt before comparing, so that a crash between compare and
	// update cannot hand out free guesses.
	ch.Attempts++
	if err := c.store.Update(ctx, ch); err != nil {
		return Outcome{}, err
	}

	if subtle.ConstantTimeCompare(
		[]byte(hashValue(code)),
		[]byte(ch.Code),
	) == 0 {
		return Outcome{Status: StatusWrongCode}, nil
	}

	// The atomic delete enforces single use: of two concurrent requests
	// carrying the correct code, only the one that performed the deletion wins.
	deleted, err := c.store.Delete(ctx, id)
	if err != nil {
		return Outcome{}, err
	}
	if !deleted {
		return Outcome{Status: StatusInvalid}, nil
	}

	return Outcome{Status: StatusOK, Owner: ch.Owner}, nil
}

// Resend rotates the code of a pending challenge and redelivers it through the
// method, which may differ from the original to switch channels. The purpose
// must match, and the challenge's handle, expiry, and attempt budget are
// preserved — resending can neither extend a login nor reset the guess budget.
//
// The fresh code is persisted before delivery, so it invalidates the previous
// one the moment it is issued: only the latest delivery can confirm the login.
func (c *Challenger) Resend(
	ctx context.Context,
	purpose, handle string,
	m Method,
) (Outcome, error) {
	id := hashValue(handle)

	ch, found, err := c.store.Get(ctx, id)
	if err != nil {
		return Outcome{}, err
	}
	if !found || ch.Purpose != purpose || c.expired(ch) {
		return Outcome{Status: StatusInvalid}, nil
	}

	if c.maxResends < 0 || ch.Resends >= c.maxResends {
		return Outcome{Status: StatusResendLimit}, nil
	}

	code, err := c.newCode(c.length)
	if err != nil {
		return Outcome{}, err
	}

	ch.Code = hashValue(code)
	ch.Resends++
	ch.MethodID = m.ID
	if err := c.store.Update(ctx, ch); err != nil {
		return Outcome{}, err
	}

	if err := m.Deliver(ctx, code); err != nil {
		return Outcome{}, err
	}

	return Outcome{
		Status:    StatusOK,
		ExpiresIn: max(ch.ExpiresAt-c.now().Unix(), 0),
	}, nil
}

// expired reports whether the challenge has passed its expiry.
func (c *Challenger) expired(ch Challenge) bool {
	return ch.ExpiresAt != 0 && c.now().Unix() > ch.ExpiresAt
}

// deleteBestEffort removes a challenge, logging but not returning a failure:
// the challenge's expiry is the backstop for a failed deletion.
func (c *Challenger) deleteBestEffort(ctx context.Context, id, what string) {
	if _, err := c.store.Delete(ctx, id); err != nil {
		c.logger.ErrorContext(ctx, "Failed to delete "+what, log.Err(err))
	}
}

// randomHandle draws a 256-bit random handle from crypto/rand.
func randomHandle() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hashValue reduces a handle or code to a digest for storage and comparison.
// The scheme need only be internally consistent, as the engine both writes and
// reads its own digests; a random 256-bit input makes SHA-256 preimage
// resistance sufficient.
func hashValue(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
