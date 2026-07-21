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

package otp_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/nexus/oauth/otp"
)

// memStore is an in-memory [otp.Store] for tests.
type memStore struct {
	mu         sync.Mutex
	items      map[string]otp.Challenge
	failCreate bool
	failGet    bool
}

func newMemStore() *memStore {
	return &memStore{items: make(map[string]otp.Challenge)}
}

func (s *memStore) Create(_ context.Context, c otp.Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failCreate {
		return errors.New("create failed")
	}
	s.items[c.ID] = c
	return nil
}

func (s *memStore) Get(
	_ context.Context, id string,
) (otp.Challenge, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failGet {
		return otp.Challenge{}, false, errors.New("get failed")
	}
	c, ok := s.items[id]
	return c, ok, nil
}

func (s *memStore) Update(_ context.Context, c otp.Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[c.ID] = c
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

// capture is a Deliverer that records the last delivered code and can be made
// to fail.
type capture struct {
	code string
	sent int
	err  error
}

func (c *capture) deliver(_ context.Context, code string) error {
	if c.err != nil {
		return c.err
	}
	c.code = code
	c.sent++
	return nil
}

func (c *capture) method(id string) otp.Method {
	return otp.Method{ID: id, Deliver: c.deliver}
}

const purpose = "test"

// fixedClock returns a clock function anchored at t.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestChallenger_New_PanicsOnNilStore(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("New did not panic on nil store")
		}
	}()
	otp.New(nil)
}

func TestChallenger_BeginVerify(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	cap := &capture{}
	c := otp.New(store)

	handle, expiresIn, err := c.Begin(
		t.Context(), purpose, "user-1", cap.method("sms"),
	)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if handle == "" {
		t.Fatal("Begin returned empty handle")
	}
	if expiresIn <= 0 {
		t.Errorf("got expiresIn %d; want > 0", expiresIn)
	}
	if cap.sent != 1 {
		t.Fatalf("code not delivered exactly once (got %d)", cap.sent)
	}
	if store.len() != 1 {
		t.Fatalf("got %d stored challenges; want 1", store.len())
	}

	out, err := c.Verify(t.Context(), purpose, handle, cap.code)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !out.OK() {
		t.Fatalf("got status %v; want OK", out.Status)
	}
	if out.Owner != "user-1" {
		t.Errorf("got owner %q; want %q", out.Owner, "user-1")
	}
	if store.len() != 0 {
		t.Errorf("challenge not consumed on success (store has %d)", store.len())
	}
}

func TestChallenger_Verify_WrongCode(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	cap := &capture{}
	c := otp.New(store)

	handle, _, err := c.Begin(t.Context(), purpose, "u", cap.method("sms"))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	out, err := c.Verify(t.Context(), purpose, handle, "000000")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.Status != otp.StatusWrongCode {
		t.Errorf("got status %v; want WrongCode", out.Status)
	}
	// A wrong guess must not consume the challenge.
	if store.len() != 1 {
		t.Errorf("wrong guess consumed the challenge")
	}
}

func TestChallenger_Verify_UnknownHandle(t *testing.T) {
	t.Parallel()

	c := otp.New(newMemStore())
	out, err := c.Verify(t.Context(), purpose, "nope", "000000")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.Status != otp.StatusInvalid {
		t.Errorf("got status %v; want Invalid", out.Status)
	}
}

func TestChallenger_Verify_PurposeMismatch(t *testing.T) {
	t.Parallel()

	cap := &capture{}
	c := otp.New(newMemStore())

	handle, _, err := c.Begin(t.Context(), "login", "u", cap.method("sms"))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	// Correct code, but presented against the wrong purpose.
	out, err := c.Verify(t.Context(), "verify:email", handle, cap.code)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.Status != otp.StatusInvalid {
		t.Errorf("got status %v; want Invalid", out.Status)
	}
}

func TestChallenger_Verify_Expired(t *testing.T) {
	t.Parallel()

	base := time.Unix(1_700_000_000, 0)
	store := newMemStore()
	cap := &capture{}
	clock := base
	c := otp.New(store,
		otp.WithLifetime(time.Minute),
		otp.WithClock(func() time.Time { return clock }),
	)

	handle, _, err := c.Begin(t.Context(), purpose, "u", cap.method("sms"))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	clock = base.Add(2 * time.Minute) // past expiry

	out, err := c.Verify(t.Context(), purpose, handle, cap.code)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.Status != otp.StatusInvalid {
		t.Errorf("got status %v; want Invalid", out.Status)
	}
}

func TestChallenger_Verify_BurnsAfterMaxAttempts(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	cap := &capture{}
	c := otp.New(store, otp.WithMaxAttempts(3))

	handle, _, err := c.Begin(t.Context(), purpose, "u", cap.method("sms"))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	// Exhaust the attempt budget with wrong codes.
	for range 3 {
		out, err := c.Verify(t.Context(), purpose, handle, "000000")
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if out.Status != otp.StatusWrongCode {
			t.Fatalf("got status %v; want WrongCode", out.Status)
		}
	}

	// The next attempt — even with the correct code — is burned.
	out, err := c.Verify(t.Context(), purpose, handle, cap.code)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.Status != otp.StatusInvalid {
		t.Errorf("got status %v; want Invalid", out.Status)
	}
	if store.len() != 0 {
		t.Errorf("burned challenge not deleted (store has %d)", store.len())
	}
}

func TestChallenger_Verify_SingleUse(t *testing.T) {
	t.Parallel()

	cap := &capture{}
	c := otp.New(newMemStore())

	handle, _, err := c.Begin(t.Context(), purpose, "u", cap.method("sms"))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	if out, _ := c.Verify(t.Context(), purpose, handle, cap.code); !out.OK() {
		t.Fatal("first Verify did not succeed")
	}
	// The handle cannot be replayed.
	out, err := c.Verify(t.Context(), purpose, handle, cap.code)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.Status != otp.StatusInvalid {
		t.Errorf("replayed handle got status %v; want Invalid", out.Status)
	}
}

func TestChallenger_Begin_DeliveryFailureCleansUp(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	boom := errors.New("boom")
	cap := &capture{err: boom}
	c := otp.New(store)

	_, _, err := c.Begin(t.Context(), purpose, "u", cap.method("sms"))
	if !errors.Is(err, boom) {
		t.Fatalf("got %v; want boom", err)
	}
	if store.len() != 0 {
		t.Errorf("undeliverable challenge left behind (store has %d)", store.len())
	}
}

func TestChallenger_Resend(t *testing.T) {
	t.Parallel()

	cap := &capture{}
	c := otp.New(newMemStore())

	handle, _, err := c.Begin(t.Context(), purpose, "u", cap.method("sms"))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	first := cap.code

	out, err := c.Resend(t.Context(), purpose, handle, cap.method("sms"))
	if err != nil {
		t.Fatalf("Resend: %v", err)
	}
	if !out.OK() {
		t.Fatalf("got status %v; want OK", out.Status)
	}
	if cap.code == first {
		t.Error("Resend did not rotate the code")
	}

	// The old code is now dead; only the fresh one verifies.
	if o, _ := c.Verify(t.Context(), purpose, handle, first); o.OK() {
		t.Error("stale code still verified after resend")
	}
	if o, _ := c.Verify(t.Context(), purpose, handle, cap.code); !o.OK() {
		t.Error("fresh code did not verify after resend")
	}
}

func TestChallenger_Resend_LimitReached(t *testing.T) {
	t.Parallel()

	cap := &capture{}
	c := otp.New(newMemStore(), otp.WithMaxResends(1))

	handle, _, err := c.Begin(t.Context(), purpose, "u", cap.method("sms"))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	if out, _ := c.Resend(t.Context(), purpose, handle, cap.method("sms")); !out.OK() {
		t.Fatal("first resend should succeed")
	}
	out, err := c.Resend(t.Context(), purpose, handle, cap.method("sms"))
	if err != nil {
		t.Fatalf("Resend: %v", err)
	}
	if out.Status != otp.StatusResendLimit {
		t.Errorf("got status %v; want ResendLimit", out.Status)
	}
}

func TestChallenger_Resend_Disabled(t *testing.T) {
	t.Parallel()

	cap := &capture{}
	c := otp.New(newMemStore(), otp.WithMaxResends(-1))

	handle, _, err := c.Begin(t.Context(), purpose, "u", cap.method("sms"))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	out, err := c.Resend(t.Context(), purpose, handle, cap.method("sms"))
	if err != nil {
		t.Fatalf("Resend: %v", err)
	}
	if out.Status != otp.StatusResendLimit {
		t.Errorf("got status %v; want ResendLimit", out.Status)
	}
}

func TestChallenger_Resend_SwitchesMethod(t *testing.T) {
	t.Parallel()

	sms := &capture{}
	email := &capture{}
	c := otp.New(newMemStore())

	handle, _, err := c.Begin(t.Context(), purpose, "u", sms.method("sms"))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	if _, err := c.Resend(
		t.Context(), purpose, handle, email.method("email"),
	); err != nil {
		t.Fatalf("Resend: %v", err)
	}
	if email.sent != 1 {
		t.Errorf("resend did not deliver over the switched method")
	}
	// The fresh code went out over email; it must verify.
	if o, _ := c.Verify(t.Context(), purpose, handle, email.code); !o.OK() {
		t.Error("code from switched method did not verify")
	}
}

func TestChallenger_Verify_StoreError(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	store.failGet = true
	c := otp.New(store)

	if _, err := c.Verify(t.Context(), purpose, "h", "000000"); err == nil {
		t.Error("expected storage error to propagate")
	}
}
