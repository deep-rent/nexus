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

package flow

import (
	"context"
	"slices"
	"time"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/iam/artifact"
	"github.com/deep-rent/nexus/sec/nonce"
	"github.com/deep-rent/nexus/sys/log"
)

// Transaction is the persisted state of an in-progress login. It holds no
// secret: the client-facing handle is stored only as its digest
// ([Transaction.ID]),
// and each step keeps its own state elsewhere.
type Transaction struct {
	// ID is the digest of the client-facing handle and the storage key.
	ID string `json:"id"`
	// Owner is an opaque reference to the authenticated subject, carried
	// through to [Result.Owner] on completion.
	Owner string `json:"owner"`
	// Completed lists the IDs of the steps finished so far, in order.
	Completed []string `json:"completed,omitzero"`
	// Remember records whether the client asked to be remembered, carried
	// through to [Result.Remember] on completion.
	Remember bool `json:"remember,omitzero"`
	// ExpiresAt is the expiry of the whole login as a Unix timestamp in
	// seconds.
	ExpiresAt int64 `json:"expires_at"`
}

// done reports whether the step with the given ID has been completed.
func (t *Transaction) done(id string) bool {
	return slices.Contains(t.Completed, id)
}

// complete records the step as finished. It reallocates Completed rather than
// appending in place, so the transaction never shares a backing array with the
// stored record — two concurrent operations on the same handle therefore cannot
// race on it.
func (t *Transaction) complete(id string) {
	t.Completed = append(slices.Clip(t.Completed), id)
}

// Store persists login transactions keyed by [Transaction.ID]. See
// [artifact.Store] for the storage contract, notably the atomic deletion the
// engine relies on to establish a login exactly once under concurrent
// completions.
type Store = artifact.Store[string, Transaction]

// Coordinator drives multi-step logins over a [Store]. It is transport-agnostic
// and does not throttle, leaving those to the caller, which maps the returned
// [Result] onto its own protocol.
//
// A Coordinator is safe for concurrent use if its [Store] is.
type Coordinator struct {
	store    Store
	lifetime time.Duration
	now      func() time.Time
	hasher   *digest.Hasher
	handles  *nonce.Generator
	logger   *log.Logger
}

// New creates a [Coordinator] backed by the given [Store]. It panics if store
// is nil, since that is a startup configuration error.
func New(store Store, opts ...Option) *Coordinator {
	if store == nil {
		panic("store is required")
	}
	c := &Coordinator{
		store:    store,
		lifetime: DefaultLifetime,
		now:      time.Now,
		hasher:   digest.DefaultHasher,
		handles:  nonce.DefaultGenerator,
		logger:   log.Discard(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Begin starts a login for an already-authenticated owner with the given
// ordered steps, activating the first and returning the client-facing handle.
//
// An empty plan means no further factors are required: no transaction is
// minted, and the result is [StatusDone] with an empty handle. The remember
// flag is carried through to completion. If activating the first step fails,
// the transaction is removed and the error returned.
func (c *Coordinator) Begin(
	ctx context.Context,
	owner string,
	remember bool,
	steps Course,
) (handle string, res Result, err error) {
	if err := steps.validate(); err != nil {
		return "", Result{}, err
	}
	if len(steps) == 0 {
		return "", Result{
			Status:   StatusDone,
			Owner:    owner,
			Remember: remember,
		}, nil
	}

	handle, err = c.handles.Draw(ctx)
	if err != nil {
		return "", Result{}, err
	}

	t := Transaction{
		ID:        c.hasher.String(handle),
		Owner:     owner,
		Remember:  remember,
		ExpiresAt: c.now().Add(c.lifetime).Unix(),
	}
	if err := c.store.Create(ctx, t); err != nil {
		return "", Result{}, err
	}

	active := steps[0]
	payload, err := active.Begin(ctx, &t, handle)
	if err != nil {
		// TODO: Log error?

		if _, err := c.store.Delete(ctx, t.ID); err != nil {
			c.logger.Error(
				ctx,
				"Could not delete unstartable transaction",
				log.Error(err),
			)
		}

		return "", Result{}, err
	}

	return handle, Result{
		Status: StatusPrompt,
		Prompt: Prompt{Step: active.ID(), Payload: payload},
	}, nil
}

// Continue verifies the client's input against the active step and advances the
// login. The caller supplies a [Plan] so the freshly-planned steps — reflecting
// any change to the owner's factors — decide what runs next.
//
// The error return is reserved for storage and step failures; all logical
// results are conveyed by the [Result].
func (c *Coordinator) Continue(
	ctx context.Context,
	handle string,
	plan Plan,
	in Input,
) (Result, error) {
	id := c.hasher.String(handle)

	t, found, err := c.store.Get(ctx, id)
	if err != nil {
		return Result{}, err
	}
	if !found || c.expired(t) {
		return Result{Status: StatusInvalid}, nil
	}

	steps, err := c.resolve(ctx, plan, t.Owner)
	if err != nil {
		return Result{}, err
	}

	active := steps.pending(&t)
	if active == nil {
		// The plan no longer has pending steps (it shrank since the last call);
		// nothing is left to prove, so the login is complete.
		return c.finish(ctx, t)
	}

	verdict, err := active.Verify(ctx, &t, handle, in)
	if err != nil {
		return Result{}, err
	}
	switch verdict {
	case VerdictReject:
		return Result{Status: StatusWrongInput}, nil
	case VerdictFail:
		if _, err := c.store.Delete(ctx, t.ID); err != nil {
			c.logger.Error(
				ctx,
				"Could not delete failed transaction",
				log.Error(err),
			)
		}

		return Result{Status: StatusInvalid}, nil
	}

	t.complete(active.ID())

	next := steps.pending(&t)
	if next == nil {
		return c.finish(ctx, t)
	}

	// Persist progress before activating the next step, so a delivery failure
	// there does not hand out a free retry of the step just completed.
	if err := c.store.Update(ctx, t); err != nil {
		return Result{}, err
	}
	payload, err := next.Begin(ctx, &t, handle)
	if err != nil {
		// TODO: Log error?

		// The next step could not be activated (e.g. its code would not send).
		// Abort the whole transaction so the client restarts from a clean slate
		// rather than being stranded on a step with no prompt.
		if _, err := c.store.Delete(ctx, t.ID); err != nil {
			c.logger.Error(
				ctx,
				"Could not delete unadvanceable transaction",
				log.Error(err),
			)
		}

		return Result{}, err
	}

	return Result{
		Status: StatusPrompt,
		Prompt: Prompt{Step: next.ID(), Payload: payload},
	}, nil
}

// Act runs an out-of-band action against the active step — resending a code or
// switching channels, say — and returns the refreshed prompt. The caller
// supplies a [Plan] to resolve the active step.
func (c *Coordinator) Act(
	ctx context.Context,
	handle string,
	plan Plan,
	a Action,
) (Result, error) {
	id := c.hasher.String(handle)

	t, found, err := c.store.Get(ctx, id)
	if err != nil {
		return Result{}, err
	}
	if !found || c.expired(t) {
		return Result{Status: StatusInvalid}, nil
	}

	steps, err := c.resolve(ctx, plan, t.Owner)
	if err != nil {
		return Result{}, err
	}

	active := steps.pending(&t)
	if active == nil {
		// The plan shrank to nothing pending since the last call, so the login
		// is already complete — mirror Continue and finish it rather than
		// rejecting an action on an effectively-done flow.
		return c.finish(ctx, t)
	}

	payload, err := active.Act(ctx, &t, handle, a)
	if err != nil {
		return Result{}, err
	}

	return Result{
		Status: StatusPrompt,
		Prompt: Prompt{Step: active.ID(), Payload: payload},
	}, nil
}

// resolve runs the plan and validates it.
func (c *Coordinator) resolve(
	ctx context.Context,
	plan Plan,
	owner string,
) (Course, error) {
	steps, err := plan(ctx, owner)
	if err != nil {
		return nil, err
	}
	if err := steps.validate(); err != nil {
		return nil, err
	}
	return steps, nil
}

// finish deletes the transaction and returns a completed result. The atomic
// delete enforces single use: of two concurrent completions, only the one that
// performs the deletion establishes the login.
func (c *Coordinator) finish(
	ctx context.Context,
	t Transaction,
) (Result, error) {
	deleted, err := c.store.Delete(ctx, t.ID)
	if err != nil {
		return Result{}, err
	}
	if !deleted {
		return Result{Status: StatusInvalid}, nil
	}
	return Result{
		Status:   StatusDone,
		Owner:    t.Owner,
		Remember: t.Remember,
	}, nil
}

// expired reports whether the transaction has passed its expiry.
func (c *Coordinator) expired(t Transaction) bool {
	return t.ExpiresAt != 0 && c.now().Unix() > t.ExpiresAt
}
