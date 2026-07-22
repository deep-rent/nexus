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
	"errors"
)

// ErrRateLimited is returned by [Step.Act] when an action is refused because a
// per-step allowance — such as a resend cap — is exhausted. It is a soft
// failure the client may retry later; transports typically map it to HTTP 429.
var ErrRateLimited = errors.New("action rate limited")

// ErrRejected is returned by [Step.Act] when an action request is malformed —
// an unsupported action or an unknown parameter. It is a client error;
// transports typically map it to HTTP 400.
var ErrRejected = errors.New("action rejected")

// Verdict is the outcome of verifying a client's input against a [Step]. It is
// the step's domain result, which the [Coordinator] translates into flow
// control and a [Result].
type Verdict int

const (
	// VerdictOK indicates the input was accepted; the flow advances to the
	// next step.
	VerdictOK Verdict = iota
	// VerdictReject indicates the input was wrong but the step remains live,
	// so the client may try again against the same prompt.
	VerdictReject
	// VerdictFail indicates the step has permanently failed — for example, its
	// attempt budget is exhausted — and the whole login must be restarted.
	VerdictFail
)

// Input carries a client's submission for the active [Step].
type Input struct {
	// Value is the primary credential when it is a simple string, such as a
	// one-time password.
	Value string
	// Raw is a structured credential payload for steps whose input is not a
	// simple string, such as a WebAuthn assertion.
	Raw []byte
	// Extra holds optional additional fields for steps that need more than a
	// single value.
	Extra map[string]string
}

// Action requests an out-of-band operation on the active [Step], such as
// resending a code or switching the delivery channel.
type Action struct {
	// Name identifies the action (e.g. "resend").
	Name string
	// Extra carries action parameters (e.g. {"channel": "email"}).
	Extra map[string]string
}

// Prompt describes what the client must do next: which step is active and any
// step-specific data needed to satisfy it.
type Prompt struct {
	// Step is the [Step.ID] of the active step.
	Step string
	// Payload is step-specific data for the client, such as the available
	// delivery channels and a code's remaining lifetime. It is opaque to the
	// engine and marshaled by the transport.
	Payload any
}

// Step is one factor in a login chain, built per-login by a [Plan] with full
// knowledge of the subject.
//
// A step owns its own state, deriving whatever it needs from the raw
// transaction handle it is given; the transaction records only which steps are
// complete. Implementations should be safe for concurrent use and honor the
// context.
type Step interface {
	// ID returns the step's identifier, stable across a single login and
	// unique within a plan (e.g. "otp", "totp"). It labels the step to the
	// client and keys the step's completion.
	ID() string
	// Begin activates the step when it becomes current — for example, by
	// delivering a code — and returns the payload describing its prompt.
	Begin(ctx context.Context, t *Transaction, handle string) (any, error)
	// Verify checks the client's input against the active step.
	Verify(
		ctx context.Context,
		t *Transaction,
		handle string,
		in Input,
	) (Verdict, error)
	// Act runs an out-of-band action on the active step and returns the
	// payload for the refreshed prompt. It may return [ErrRateLimited] as a
	// soft failure. A step that supports no actions returns an error.
	Act(
		ctx context.Context,
		t *Transaction,
		handle string,
		a Action,
	) (any, error)
}

// Plan produces the ordered steps for a login given the owner recorded in the
// transaction. It is invoked on every continuation, so changes to the owner's
// enrolled factors take effect mid-login. Returning an empty slice means no
// (further) factors are required.
type Plan func(ctx context.Context, owner string) ([]Step, error)

// Status is the logical result of a [Coordinator] operation.
type Status int

const (
	// StatusPrompt indicates a step awaits the client; [Result.Prompt] is set.
	StatusPrompt Status = iota
	// StatusDone indicates every step is complete and the login may be
	// established; [Result.Owner] and [Result.Remember] are set.
	StatusDone
	// StatusWrongInput indicates the active step rejected the input but remains
	// live, so the client may retry.
	StatusWrongInput
	// StatusInvalid indicates the transaction is absent, expired, or was
	// aborted by a failed step. The reasons are collapsed so callers cannot
	// leak which applies.
	StatusInvalid
)

// Result carries the outcome of a [Coordinator] operation.
type Result struct {
	// Status is the logical result.
	Status Status
	// Prompt describes the next step; set when Status is [StatusPrompt].
	Prompt Prompt
	// Owner is the authenticated owner; set when Status is [StatusDone].
	Owner string
	// Remember reports whether the client asked to be remembered; set when
	// Status is [StatusDone].
	Remember bool
}

// Done reports whether the flow has completed and a login may be established.
func (r Result) Done() bool { return r.Status == StatusDone }
