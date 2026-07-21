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
	"sync"
	"testing"

	"github.com/deep-rent/nexus/oauth/flow"
	"github.com/deep-rent/nexus/oauth/otp"
)

// memOTPStore is an in-memory [otp.Store] for these tests.
type memOTPStore struct {
	mu    sync.Mutex
	items map[string]otp.Challenge
}

func (s *memOTPStore) Create(_ context.Context, c otp.Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[c.ID] = c
	return nil
}

func (s *memOTPStore) Get(
	_ context.Context, id string,
) (otp.Challenge, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.items[id]
	return c, ok, nil
}

func (s *memOTPStore) Update(_ context.Context, c otp.Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[c.ID] = c
	return nil
}

func (s *memOTPStore) Delete(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return false, nil
	}
	delete(s.items, id)
	return true, nil
}

// memFlowStore is an in-memory [flow.Store] for these tests.
type memFlowStore struct {
	mu    sync.Mutex
	items map[string]flow.Transaction
}

func (s *memFlowStore) Create(_ context.Context, t flow.Transaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[t.ID] = t
	return nil
}

func (s *memFlowStore) Get(
	_ context.Context, id string,
) (flow.Transaction, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.items[id]
	return t, ok, nil
}

func (s *memFlowStore) Update(_ context.Context, t flow.Transaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[t.ID] = t
	return nil
}

func (s *memFlowStore) Delete(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return false, nil
	}
	delete(s.items, id)
	return true, nil
}

// recordingMethod is an [otp.Method] that records the codes it delivers.
type recordingMethod struct {
	id    string
	codes []string
}

func (m *recordingMethod) method() otp.Method {
	return otp.Method{ID: m.id, Deliver: func(_ context.Context, code string) error {
		m.codes = append(m.codes, code)
		return nil
	}}
}

func (m *recordingMethod) last(t *testing.T) string {
	t.Helper()
	if len(m.codes) == 0 {
		t.Fatal("no code delivered")
	}
	return m.codes[len(m.codes)-1]
}

// otpStepFixture wires a flow Coordinator over an OTP step for testing.
type otpStepFixture struct {
	coord *flow.Coordinator
	sms   *recordingMethod
	email *recordingMethod
	step  flow.Step
	plan  flow.Plan
}

func newOTPStepFixture(t *testing.T, multi bool) *otpStepFixture {
	t.Helper()
	ch := otp.New(&memOTPStore{items: make(map[string]otp.Challenge)})
	coord := flow.New(&memFlowStore{items: make(map[string]flow.Transaction)})

	sms := &recordingMethod{id: "sms"}
	email := &recordingMethod{id: "email"}
	methods := []otp.Method{sms.method()}
	if multi {
		methods = append(methods, email.method())
	}

	step := OTPStep("otp", ch, methods)
	return &otpStepFixture{
		coord: coord,
		sms:   sms,
		email: email,
		step:  step,
		plan: func(context.Context, string) ([]flow.Step, error) {
			return []flow.Step{step}, nil
		},
	}
}

func (f *otpStepFixture) begin(t *testing.T, remember bool) (string, flow.Result) {
	t.Helper()
	handle, res, err := f.coord.Begin(
		t.Context(), "user-1", remember, []flow.Step{f.step},
	)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	return handle, res
}

func TestOTPStep_FullLogin(t *testing.T) {
	t.Parallel()
	f := newOTPStepFixture(t, false)

	handle, res := f.begin(t, false)
	if res.Status != flow.StatusPrompt || res.Prompt.Step != "otp" {
		t.Fatalf("got %v/%q; want Prompt/otp", res.Status, res.Prompt.Step)
	}
	payload, ok := res.Prompt.Payload.(otpChallengePayload)
	if !ok {
		t.Fatalf("got payload %T; want otpChallengePayload", res.Prompt.Payload)
	}
	if payload.ExpiresIn <= 0 {
		t.Errorf("got expires_in %d; want > 0", payload.ExpiresIn)
	}
	if payload.Channels != nil {
		t.Errorf("single method should not advertise channels")
	}

	res, err := f.coord.Continue(t.Context(), handle, f.plan, flow.Input{Value: f.sms.last(t)})
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if !res.Done() {
		t.Fatalf("got status %v; want Done", res.Status)
	}
	if res.Owner != "user-1" {
		t.Errorf("got owner %q; want user-1", res.Owner)
	}
}

func TestOTPStep_WrongThenRight(t *testing.T) {
	t.Parallel()
	f := newOTPStepFixture(t, false)
	handle, _ := f.begin(t, false)

	res, err := f.coord.Continue(t.Context(), handle, f.plan, flow.Input{Value: "000000"})
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if res.Status != flow.StatusWrongInput {
		t.Fatalf("got %v; want WrongInput", res.Status)
	}

	res, err = f.coord.Continue(t.Context(), handle, f.plan, flow.Input{Value: f.sms.last(t)})
	if err != nil {
		t.Fatalf("Continue retry: %v", err)
	}
	if !res.Done() {
		t.Errorf("got %v; want Done", res.Status)
	}
}

func TestOTPStep_ResendAndSwitchChannel(t *testing.T) {
	t.Parallel()
	f := newOTPStepFixture(t, true)
	handle, res := f.begin(t, false)

	// Multiple methods advertise a picker.
	payload := res.Prompt.Payload.(otpChallengePayload)
	if len(payload.Channels) != 2 {
		t.Fatalf("got %d channels; want 2", len(payload.Channels))
	}

	first := f.sms.last(t)

	// Resend over the default channel rotates the code.
	if _, err := f.coord.Act(
		t.Context(), handle, f.plan, flow.Action{Name: ActionResend},
	); err != nil {
		t.Fatalf("Act resend: %v", err)
	}
	if f.sms.last(t) == first {
		t.Error("resend did not rotate the code")
	}

	// Switch to email and complete with the email code.
	if _, err := f.coord.Act(
		t.Context(), handle, f.plan,
		flow.Action{Name: ActionResend, Extra: map[string]string{"channel": "email"}},
	); err != nil {
		t.Fatalf("Act switch: %v", err)
	}
	if len(f.email.codes) != 1 {
		t.Fatalf("got %d email deliveries; want 1", len(f.email.codes))
	}
	res, err := f.coord.Continue(t.Context(), handle, f.plan, flow.Input{Value: f.email.last(t)})
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if !res.Done() {
		t.Errorf("got %v; want Done", res.Status)
	}
}

func TestOTPStep_Panics(t *testing.T) {
	t.Parallel()
	ch := otp.New(&memOTPStore{items: make(map[string]otp.Challenge)})
	m := (&recordingMethod{id: "sms"}).method()

	cases := []struct {
		name    string
		id      string
		ch      *otp.Challenger
		methods []otp.Method
	}{
		{"empty id", "", ch, []otp.Method{m}},
		{"nil challenger", "otp", nil, []otp.Method{m}},
		{"no methods", "otp", ch, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Error("OTPStep did not panic")
				}
			}()
			OTPStep(tc.id, tc.ch, tc.methods)
		})
	}
}
