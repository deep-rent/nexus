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
	"context"
	"fmt"

	"github.com/deep-rent/nexus/oauth/flow"
	"github.com/deep-rent/nexus/oauth/otp"
)

// purposeLogin namespaces one-time password challenges minted for login flow
// steps within the challenge store.
const purposeLogin = "login"

// ActionResend is the [flow.Action] name an [OTPStep] understands: it
// redelivers the code, optionally over a different channel named by the
// "channel" action parameter.
const ActionResend = "resend"

// Device describes the requesting client for planning purposes, notably whether
// it presented a valid remember-me trust token. It lets a [Planner] skip
// factors on a device the subject has already trusted.
type Device struct {
	// Trusted reports whether the request carried a valid device-trust token.
	Trusted bool
	// ID is an opaque identifier of the trusted device, set when Trusted.
	ID string
}

// Planner decides the authentication steps for a subject on a given device.
//
// It runs after the identifying factor (e.g. a password) has been verified, and
// again on every continuation, so a change to the subject's enrolled factors —
// or the device's trust — takes effect mid-login. Returning an empty slice
// completes the login with no further factors.
type Planner func(
	ctx context.Context,
	sub Subject,
	dev Device,
) ([]flow.Step, error)

// otpChallengePayload is the client-facing prompt an [OTPStep] returns: the
// channels the code may be delivered over and the code's remaining lifetime.
type otpChallengePayload struct {
	// Channels lists the enrolled delivery methods for a client-side picker. It
	// is omitted when only a single method is enrolled.
	Channels []Channel `json:"channels,omitzero"`
	// ExpiresIn is the remaining lifetime of the code in seconds.
	ExpiresIn int64 `json:"expires_in"`
}

// otpStep is a [flow.Step] that delivers and verifies a one-time password over
// a subject's enrolled methods, composing an [otp.Challenger].
type otpStep struct {
	id      string
	ch      *otp.Challenger
	methods []otp.Method
}

var _ flow.Step = (*otpStep)(nil)

// OTPStep returns a [flow.Step] that delivers a one-time password over the
// subject's enrolled methods and verifies the code the subject returns.
//
// It composes the given [otp.Challenger], keying the challenge on a value
// derived from the flow handle and the step id, so the client holds only the
// single flow handle for the whole login. The methods are ordered, most
// preferred first; the client may switch channels on resend by [Channel.ID].
//
// It panics if id is empty, ch is nil, or methods is empty — all startup
// configuration errors.
func OTPStep(id string, ch *otp.Challenger, methods []otp.Method) flow.Step {
	if id == "" {
		panic("step ID is required")
	}
	if ch == nil {
		panic("challenger is required")
	}
	if len(methods) == 0 {
		panic("at least one method is required")
	}
	return &otpStep{id: id, ch: ch, methods: methods}
}

// ID implements [flow.Step].
func (s *otpStep) ID() string { return s.id }

// handle derives the per-step challenge handle from the outer flow handle. The
// flow handle is high-entropy, so the derived value is too.
func (s *otpStep) handle(flowHandle string) string {
	return flowHandle + ":" + s.id
}

// Begin implements [flow.Step]: it delivers a fresh code over the default
// method and returns the prompt.
func (s *otpStep) Begin(
	ctx context.Context,
	t *flow.Transaction,
	handle string,
) (any, error) {
	m := s.methods[0]
	expiresIn, err := s.ch.Start(ctx, purposeLogin, t.Owner, s.handle(handle), m)
	if err != nil {
		return nil, err
	}
	return s.payload(expiresIn), nil
}

// Verify implements [flow.Step]: it confirms the submitted code, translating
// the challenge outcome into a [flow.Verdict].
func (s *otpStep) Verify(
	ctx context.Context,
	_ *flow.Transaction,
	handle string,
	in flow.Input,
) (flow.Verdict, error) {
	out, err := s.ch.Verify(ctx, purposeLogin, s.handle(handle), in.Value)
	if err != nil {
		return 0, err
	}
	switch out.Status {
	case otp.StatusOK:
		return flow.VerdictOK, nil
	case otp.StatusWrongCode:
		return flow.VerdictReject, nil
	default:
		// Absent, expired, or burned: the factor can no longer be satisfied, so
		// the login must restart.
		return flow.VerdictFail, nil
	}
}

// Act implements [flow.Step]: it handles [ActionResend], redelivering the code
// over the default or a client-selected channel.
func (s *otpStep) Act(
	ctx context.Context,
	_ *flow.Transaction,
	handle string,
	a flow.Action,
) (any, error) {
	if a.Name != ActionResend {
		return nil, fmt.Errorf("otp step: unsupported action %q", a.Name)
	}

	m := s.methods[0]
	if id := a.Extra["channel"]; id != "" {
		picked, ok := pickMethod(s.methods, id)
		if !ok {
			return nil, fmt.Errorf("otp step: unknown channel %q", id)
		}
		m = picked
	}

	out, err := s.ch.Resend(ctx, purposeLogin, s.handle(handle), m)
	if err != nil {
		return nil, err
	}
	switch out.Status {
	case otp.StatusOK:
		return s.payload(out.ExpiresIn), nil
	case otp.StatusResendLimit:
		return nil, flow.ErrRateLimited
	default:
		return nil, fmt.Errorf("otp step: challenge is no longer resendable")
	}
}

// payload builds the client-facing prompt, advertising the method picker only
// when more than one method is enrolled.
func (s *otpStep) payload(expiresIn int64) otpChallengePayload {
	var channels []Channel
	if len(s.methods) > 1 {
		channels = make([]Channel, len(s.methods))
		for i, m := range s.methods {
			channels[i] = Channel{ID: m.ID, Label: m.Label}
		}
	}
	return otpChallengePayload{Channels: channels, ExpiresIn: expiresIn}
}

// pickMethod returns the method with the given ID, or false when none matches.
func pickMethod(methods []otp.Method, id string) (otp.Method, bool) {
	for _, m := range methods {
		if m.ID == id {
			return m, true
		}
	}
	return otp.Method{}, false
}
