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
	"time"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/iam/artifact"
	"github.com/deep-rent/nexus/sec/nonce"
	"github.com/deep-rent/nexus/std/clock"
	"github.com/deep-rent/nexus/sys/log"
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
	ID string `json:"id"`
	// Code is the digest of the current one-time password.
	Code string `json:"code"`
	// Owner is an opaque reference to whoever the challenge authenticates
	// (e.g. a subject ID). It is returned verbatim on successful verification.
	Owner string `json:"owner"`
	// Purpose namespaces distinct flows (e.g. "2fa", "verify:email") so that a
	// handle minted for one flow cannot complete another.
	Purpose string `json:"purpose"`
	// MethodID records the [Method] that last delivered the code, so a resend
	// can default to the same channel.
	MethodID string `json:"method_id,omitzero"`
	// ExpiresAt is the expiry as a Unix timestamp in seconds. A resend does not
	// extend it.
	ExpiresAt int64 `json:"expires_at"`
	// Attempts is the number of confirmations tried so far.
	Attempts int `json:"attempts,omitzero"`
	// Resends is the number of times the code has been redelivered.
	Resends int `json:"resends,omitzero"`
}

// Store persists pending challenges keyed by [Challenge.ID]. See
// [artifact.Store] for the storage contract, notably the atomic deletion the
// engine relies on to enforce single use under concurrent confirmations.
type Store = artifact.Store[string, Challenge]

// Challenger runs the lifecycle of one-time password challenges — minting,
// delivering, verifying, and resending them — over a [Store]. It is
// transport-agnostic: it neither speaks HTTP nor throttles, leaving those to
// the caller, which maps the returned [Outcome] onto its own protocol.
//
// A Challenger is safe for concurrent use if its [Store] is.
type Challenger struct {
	store       Store
	lifetime    time.Duration
	maxAttempts int
	maxResends  int
	now         clock.Clock
	hasher      *digest.Hasher
	handles     *nonce.Generator
	codes       *nonce.Sampler
	logger      *log.Logger
}

// New creates a [Challenger] backed by the given [Store]. It panics if store
// is nil, since that is a startup configuration error.
func New(store Store, opts ...Option) *Challenger {
	if store == nil {
		panic("store is required")
	}
	c := &Challenger{
		store:       store,
		lifetime:    DefaultLifetime,
		maxAttempts: DefaultMaxAttempts,
		maxResends:  DefaultMaxResends,
		now:         clock.System,
		hasher:      digest.DefaultHasher,
		handles:     nonce.DefaultGenerator,
		codes:       defaultCodes,
		logger:      log.Discard(),
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
	handle, err = c.handles.Draw(ctx)
	if err != nil {
		return "", 0, err
	}
	expiresIn, err = c.Start(ctx, purpose, owner, handle, m)
	if err != nil {
		return "", 0, err
	}
	return handle, expiresIn, nil
}

// Start mints a challenge under a caller-provided handle instead of a generated
// one, and otherwise behaves exactly like [Challenger.Begin]. It lets a caller
// derive the handle deterministically — for example, a login step keying its
// challenge on an outer flow handle so the client holds a single token.
//
// The handle MUST be unpredictable: the challenge is only as unguessable as the
// handle it is keyed on. Deriving it from a high-entropy secret satisfies this;
// a low-entropy handle would make the code brute-forceable through the store.
func (c *Challenger) Start(
	ctx context.Context,
	purpose, owner, handle string,
	m Method,
) (expiresIn int64, err error) {
	code, err := c.codes.Draw(ctx)
	if err != nil {
		return 0, err
	}

	ch := Challenge{
		ID:        c.hasher.String(handle),
		Code:      c.hasher.String(code),
		Owner:     owner,
		Purpose:   purpose,
		MethodID:  m.ID,
		ExpiresAt: c.now().Add(c.lifetime).Unix(),
	}
	if err := c.store.Create(ctx, ch); err != nil {
		return 0, err
	}

	if err := m.Deliver(ctx, code); err != nil {
		c.deleteBestEffort(ctx, ch.ID, "undeliverable challenge")
		return 0, err
	}

	return int64(c.lifetime.Seconds()), nil
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
	id := c.hasher.String(handle)

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

	// Match hashes the submitted code and compares it against the stored digest
	// in constant time.
	if !c.hasher.Match(code, ch.Code) {
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
	id := c.hasher.String(handle)

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

	code, err := c.codes.Draw(ctx)
	if err != nil {
		return Outcome{}, err
	}

	ch.Code = c.hasher.String(code)
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

// Peek returns the owner recorded for a live challenge without modifying it, so
// a caller can resolve delivery details (for example, re-read a subject's
// enrollment) before a [Challenger.Resend]. ok is false when the challenge is
// absent, expired, or belongs to another purpose; the error is reserved for
// storage failures.
func (c *Challenger) Peek(
	ctx context.Context,
	purpose, handle string,
) (owner string, ok bool, err error) {
	ch, found, err := c.store.Get(ctx, c.hasher.String(handle))
	if err != nil {
		return "", false, err
	}
	if !found || ch.Purpose != purpose || c.expired(ch) {
		return "", false, nil
	}
	return ch.Owner, true, nil
}

// Cancel removes a pending challenge, reporting whether one existed. Holding
// the handle is sufficient authority to cancel, so no purpose is required. It
// is a no-op, returning (false, nil), when no such challenge exists.
func (c *Challenger) Cancel(
	ctx context.Context,
	handle string,
) (bool, error) {
	return c.store.Delete(ctx, c.hasher.String(handle))
}

// expired reports whether the challenge has passed its expiry.
func (c *Challenger) expired(ch Challenge) bool {
	return ch.ExpiresAt != 0 && c.now().Unix() > ch.ExpiresAt
}

// deleteBestEffort removes a challenge, logging but not returning a failure:
// the challenge's expiry is the backstop for a failed deletion.
func (c *Challenger) deleteBestEffort(ctx context.Context, id, what string) {
	if _, err := c.store.Delete(ctx, id); err != nil {
		c.logger.Error(ctx, "Failed to delete "+what, log.Error(err))
	}
}

// defaultCodes samples [DefaultLength] digits from [Digits], matching the
// format users know from TOTP authenticator apps.
var defaultCodes = nonce.NewSampler(nil, Digits, DefaultLength)
