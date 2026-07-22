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

package flow_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/nexus/oauth/flow"
)

// memStore is an in-memory [flow.Store] for tests.
type memStore struct {
	mu    sync.Mutex
	items map[string]flow.Transaction
}

func newMemStore() *memStore {
	return &memStore{items: make(map[string]flow.Transaction)}
}

func (s *memStore) Create(_ context.Context, t flow.Transaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[t.ID] = t
	return nil
}

func (s *memStore) Get(
	_ context.Context, id string,
) (flow.Transaction, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.items[id]
	return t, ok, nil
}

func (s *memStore) Update(_ context.Context, t flow.Transaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[t.ID] = t
	return nil
}

func (s *memStore) Delete(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return false, nil
	}
	delete(s.items, id)
	return true, nil
}

func (s *memStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// fakeStep is a configurable [flow.Step] recording its calls.
type fakeStep struct {
	id       string
	verdict  flow.Verdict
	beginErr error
	actErr   error
	begins   int
	verifies int
	acts     int
}

func (s *fakeStep) ID() string { return s.id }

func (s *fakeStep) Begin(
	_ context.Context, _ *flow.Transaction, _ string,
) (any, error) {
	s.begins++
	if s.beginErr != nil {
		return nil, s.beginErr
	}
	return map[string]any{"step": s.id}, nil
}

func (s *fakeStep) Verify(
	_ context.Context, _ *flow.Transaction, _ string, _ flow.Input,
) (flow.Verdict, error) {
	s.verifies++
	return s.verdict, nil
}

func (s *fakeStep) Act(
	_ context.Context, _ *flow.Transaction, _ string, _ flow.Action,
) (any, error) {
	s.acts++
	if s.actErr != nil {
		return nil, s.actErr
	}
	return map[string]any{"resent": s.id}, nil
}

// planOf returns a [flow.Plan] yielding the given steps.
func planOf(steps ...flow.Step) flow.Plan {
	return func(context.Context, string) ([]flow.Step, error) {
		return steps, nil
	}
}

var code = flow.Input{Value: "123456"}

func TestNew_PanicsOnNilStore(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("New did not panic on nil store")
		}
	}()
	flow.New(nil)
}

func TestBegin_EmptyPlanCompletesImmediately(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c := flow.New(store)

	handle, res, err := c.Begin(t.Context(), "user-1", true, nil)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if !res.Done() {
		t.Fatalf("got status %v; want Done", res.Status)
	}
	if handle != "" {
		t.Errorf("got handle %q; want empty for an immediate completion", handle)
	}
	if res.Owner != "user-1" || !res.Remember {
		t.Errorf("got owner=%q remember=%v; want user-1/true", res.Owner, res.Remember)
	}
	if store.len() != 0 {
		t.Error("no transaction should be minted for an empty plan")
	}
}

func TestBeginContinue_SingleStep(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c := flow.New(store)
	step := &fakeStep{id: "otp", verdict: flow.VerdictOK}

	handle, res, err := c.Begin(t.Context(), "user-1", false, []flow.Step{step})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if res.Status != flow.StatusPrompt {
		t.Fatalf("got status %v; want Prompt", res.Status)
	}
	if handle == "" {
		t.Fatal("Begin returned empty handle")
	}
	if res.Prompt.Step != "otp" {
		t.Errorf("got prompt step %q; want otp", res.Prompt.Step)
	}
	if step.begins != 1 {
		t.Errorf("step begun %d times; want 1", step.begins)
	}
	if store.len() != 1 {
		t.Fatalf("got %d transactions; want 1", store.len())
	}

	res, err = c.Continue(t.Context(), handle, planOf(step), code)
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if !res.Done() {
		t.Fatalf("got status %v; want Done", res.Status)
	}
	if res.Owner != "user-1" {
		t.Errorf("got owner %q; want user-1", res.Owner)
	}
	if store.len() != 0 {
		t.Error("transaction should be consumed on completion")
	}
}

func TestContinue_TwoStepsInOrder(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c := flow.New(store)
	s1 := &fakeStep{id: "password-otp", verdict: flow.VerdictOK}
	s2 := &fakeStep{id: "email-otp", verdict: flow.VerdictOK}
	steps := []flow.Step{s1, s2}

	handle, res, err := c.Begin(t.Context(), "u", false, steps)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if res.Prompt.Step != "password-otp" {
		t.Fatalf("got first prompt %q; want password-otp", res.Prompt.Step)
	}

	// Completing the first step activates the second.
	res, err = c.Continue(t.Context(), handle, planOf(steps...), code)
	if err != nil {
		t.Fatalf("Continue 1: %v", err)
	}
	if res.Status != flow.StatusPrompt || res.Prompt.Step != "email-otp" {
		t.Fatalf("got %v/%q; want Prompt/email-otp", res.Status, res.Prompt.Step)
	}
	if s2.begins != 1 {
		t.Errorf("second step begun %d times; want 1", s2.begins)
	}

	// Completing the second finishes the login.
	res, err = c.Continue(t.Context(), handle, planOf(steps...), code)
	if err != nil {
		t.Fatalf("Continue 2: %v", err)
	}
	if !res.Done() {
		t.Fatalf("got status %v; want Done", res.Status)
	}
}

func TestContinue_WrongInputStaysLive(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c := flow.New(store)
	step := &fakeStep{id: "otp", verdict: flow.VerdictReject}

	handle, _, err := c.Begin(t.Context(), "u", false, []flow.Step{step})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	res, err := c.Continue(t.Context(), handle, planOf(step), code)
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if res.Status != flow.StatusWrongInput {
		t.Errorf("got status %v; want WrongInput", res.Status)
	}
	if store.len() != 1 {
		t.Error("a wrong input must not consume the transaction")
	}

	// A subsequent correct input completes the login.
	step.verdict = flow.VerdictOK
	res, err = c.Continue(t.Context(), handle, planOf(step), code)
	if err != nil {
		t.Fatalf("Continue retry: %v", err)
	}
	if !res.Done() {
		t.Errorf("got status %v; want Done after retry", res.Status)
	}
}

func TestContinue_StepFailAborts(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c := flow.New(store)
	step := &fakeStep{id: "otp", verdict: flow.VerdictFail}

	handle, _, err := c.Begin(t.Context(), "u", false, []flow.Step{step})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	res, err := c.Continue(t.Context(), handle, planOf(step), code)
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if res.Status != flow.StatusInvalid {
		t.Errorf("got status %v; want Invalid", res.Status)
	}
	if store.len() != 0 {
		t.Error("a failed step must abort and delete the transaction")
	}
}

func TestContinue_UnknownAndExpired(t *testing.T) {
	t.Parallel()

	t.Run("unknown handle", func(t *testing.T) {
		t.Parallel()
		c := flow.New(newMemStore())
		res, err := c.Continue(t.Context(), "nope", planOf(), code)
		if err != nil {
			t.Fatalf("Continue: %v", err)
		}
		if res.Status != flow.StatusInvalid {
			t.Errorf("got status %v; want Invalid", res.Status)
		}
	})

	t.Run("expired transaction", func(t *testing.T) {
		t.Parallel()
		base := time.Unix(1_700_000_000, 0)
		clock := base
		step := &fakeStep{id: "otp", verdict: flow.VerdictOK}
		c := flow.New(newMemStore(),
			flow.WithLifetime(time.Minute),
			flow.WithClock(func() time.Time { return clock }),
		)

		handle, _, err := c.Begin(t.Context(), "u", false, []flow.Step{step})
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		clock = base.Add(2 * time.Minute)

		res, err := c.Continue(t.Context(), handle, planOf(step), code)
		if err != nil {
			t.Fatalf("Continue: %v", err)
		}
		if res.Status != flow.StatusInvalid {
			t.Errorf("got status %v; want Invalid", res.Status)
		}
	})
}

func TestContinue_ReplanGrows(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c := flow.New(store)
	s1 := &fakeStep{id: "otp", verdict: flow.VerdictOK}
	s2 := &fakeStep{id: "email", verdict: flow.VerdictOK}

	// The login begins with a single-step plan.
	handle, _, err := c.Begin(t.Context(), "u", false, []flow.Step{s1})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	// By continuation, a second factor has been added to the plan.
	res, err := c.Continue(t.Context(), handle, planOf(s1, s2), code)
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if res.Status != flow.StatusPrompt || res.Prompt.Step != "email" {
		t.Fatalf("got %v/%q; want Prompt/email", res.Status, res.Prompt.Step)
	}
}

func TestContinue_ReplanShrinks(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c := flow.New(store)
	s1 := &fakeStep{id: "otp", verdict: flow.VerdictOK}
	s2 := &fakeStep{id: "email", verdict: flow.VerdictOK}

	handle, _, err := c.Begin(t.Context(), "u", false, []flow.Step{s1, s2})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	// The second factor is dropped from the plan before the first completes.
	res, err := c.Continue(t.Context(), handle, planOf(s1), code)
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if !res.Done() {
		t.Errorf("got status %v; want Done once the plan shrank", res.Status)
	}
}

func TestAct(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c := flow.New(store)
	step := &fakeStep{id: "otp", verdict: flow.VerdictOK}

	handle, _, err := c.Begin(t.Context(), "u", false, []flow.Step{step})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	res, err := c.Act(t.Context(), handle, planOf(step), flow.Action{Name: "resend"})
	if err != nil {
		t.Fatalf("Act: %v", err)
	}
	if res.Status != flow.StatusPrompt || res.Prompt.Step != "otp" {
		t.Errorf("got %v/%q; want Prompt/otp", res.Status, res.Prompt.Step)
	}
	if step.acts != 1 {
		t.Errorf("step acted %d times; want 1", step.acts)
	}
}

func TestAct_PropagatesRateLimit(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c := flow.New(store)
	step := &fakeStep{id: "otp", verdict: flow.VerdictOK, actErr: flow.ErrRateLimited}

	handle, _, err := c.Begin(t.Context(), "u", false, []flow.Step{step})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	if _, err := c.Act(
		t.Context(), handle, planOf(step), flow.Action{Name: "resend"},
	); !errors.Is(err, flow.ErrRateLimited) {
		t.Errorf("got %v; want ErrRateLimited", err)
	}
}

func TestPlan_RejectsDuplicateStepIDs(t *testing.T) {
	t.Parallel()
	c := flow.New(newMemStore())
	s1 := &fakeStep{id: "otp", verdict: flow.VerdictOK}
	s2 := &fakeStep{id: "otp", verdict: flow.VerdictOK}

	if _, _, err := c.Begin(
		t.Context(), "u", false, []flow.Step{s1, s2},
	); err == nil {
		t.Error("Begin accepted a plan with duplicate step IDs")
	}
}

func TestContinue_SingleUse(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c := flow.New(store)
	step := &fakeStep{id: "otp", verdict: flow.VerdictOK}

	handle, _, err := c.Begin(t.Context(), "u", false, []flow.Step{step})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if res, _ := c.Continue(t.Context(), handle, planOf(step), code); !res.Done() {
		t.Fatal("first completion did not finish")
	}
	// The handle cannot be replayed.
	res, err := c.Continue(t.Context(), handle, planOf(step), code)
	if err != nil {
		t.Fatalf("Continue replay: %v", err)
	}
	if res.Status != flow.StatusInvalid {
		t.Errorf("replayed handle got status %v; want Invalid", res.Status)
	}
}

func TestContinue_AdvanceFailureAborts(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c := flow.New(store)
	s1 := &fakeStep{id: "otp", verdict: flow.VerdictOK}
	s2 := &fakeStep{id: "email", verdict: flow.VerdictOK, beginErr: errors.New("sms down")}

	handle, _, err := c.Begin(t.Context(), "u", false, []flow.Step{s1, s2})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	// The first step passes, but activating the second fails to deliver.
	if _, err := c.Continue(
		t.Context(), handle, planOf(s1, s2), code,
	); err == nil {
		t.Error("expected the advance failure to surface as an error")
	}
	if store.len() != 0 {
		t.Error("an unadvanceable transaction should be deleted")
	}
}

func TestBegin_ActivationFailureCleansUp(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	c := flow.New(store)
	step := &fakeStep{id: "otp", beginErr: errors.New("sms down")}

	if _, _, err := c.Begin(
		t.Context(), "u", false, []flow.Step{step},
	); err == nil {
		t.Error("expected the activation failure to surface as an error")
	}
	if store.len() != 0 {
		t.Error("an unstartable transaction should be deleted")
	}
}
