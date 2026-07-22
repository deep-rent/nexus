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

package iam

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/deep-rent/nexus/net/throttle"
	"github.com/deep-rent/nexus/sec/iam/flow"
	"github.com/deep-rent/nexus/sec/iam/otp"
	"github.com/deep-rent/nexus/sec/iam/trust"
)

// flowEnv wraps a testEnv whose planner requires a single OTP step (unless the
// device is trusted), delivering over recording methods.
type flowEnv struct {
	*testEnv
	sms   *recordingMethod
	email *recordingMethod
}

func newFlowEnv(t *testing.T, opts ...Option) *flowEnv {
	t.Helper()
	sms := &recordingMethod{id: "sms"}
	email := &recordingMethod{id: "email"}

	planner := func(
		_ context.Context, _ Subject, dev trust.Device, b Steps,
	) ([]flow.Step, error) {
		if dev.Trusted {
			return nil, nil
		}
		return []flow.Step{
			b.OTP("otp", []otp.Method{sms.method(), email.method()}),
		}, nil
	}

	opts = append([]Option{WithFlow(planner)}, opts...)
	return &flowEnv{
		testEnv: newTestEnv(t, opts...),
		sms:     sms,
		email:   email,
	}
}

func trustCookie(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == DefaultTrustCookieName {
			return c
		}
	}
	return nil
}

// login performs the password phase and returns the flow response.
func (env *flowEnv) login(t *testing.T, remember bool) FlowResponse {
	t.Helper()
	body := fmt.Sprintf(
		`{"username":"alice","password":"wonderland","remember":%t}`, remember,
	)
	w := postJSON(env.testEnv, PathLogin, body)
	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
	}
	if sessionCookie(w) != nil {
		t.Fatal("no session before the flow completes")
	}
	return decodeJSON[FlowResponse](t, w)
}

func TestFlowLogin_BeginsFlow(t *testing.T) {
	t.Parallel()
	env := newFlowEnv(t)

	res := env.login(t, false)

	if res.Handle == "" {
		t.Fatal("missing flow handle")
	}
	if res.Step != "otp" {
		t.Errorf("got step %q; want otp", res.Step)
	}
	if len(env.sms.codes) != 1 {
		t.Errorf("got %d codes delivered; want 1", len(env.sms.codes))
	}
}

func TestFlowContinue_Completes(t *testing.T) {
	t.Parallel()
	env := newFlowEnv(t)
	res := env.login(t, false)

	w := postJSON(env.testEnv, PathLoginContinue, fmt.Sprintf(
		`{"handle":%q,"code":%q}`, res.Handle, env.sms.last(t),
	))
	if w.Code != http.StatusNoContent {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusNoContent, w.Body)
	}
	if sessionCookie(w) == nil {
		t.Error("missing session cookie after completion")
	}
	if len(env.sessions.flowTransactions) != 0 {
		t.Error("flow transaction should be consumed on completion")
	}
}

func TestFlowContinue_WrongThenRight(t *testing.T) {
	t.Parallel()
	env := newFlowEnv(t)
	res := env.login(t, false)

	w := postJSON(env.testEnv, PathLoginContinue, fmt.Sprintf(
		`{"handle":%q,"code":"000000"}`, res.Handle,
	))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
	}

	w = postJSON(env.testEnv, PathLoginContinue, fmt.Sprintf(
		`{"handle":%q,"code":%q}`, res.Handle, env.sms.last(t),
	))
	if w.Code != http.StatusNoContent {
		t.Fatalf("got status %d; want %d", w.Code, http.StatusNoContent)
	}
}

func TestFlowContinue_UnknownHandle(t *testing.T) {
	t.Parallel()
	env := newFlowEnv(t)

	w := postJSON(env.testEnv, PathLoginContinue,
		`{"handle":"no-such-handle","code":"123456"}`,
	)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestFlowAction_ResendAndSwitch(t *testing.T) {
	t.Parallel()
	env := newFlowEnv(t)
	res := env.login(t, false)
	first := env.sms.last(t)

	// Resend rotates the code on the default channel.
	w := postJSON(env.testEnv, PathLoginAction, fmt.Sprintf(
		`{"handle":%q,"action":"resend"}`, res.Handle,
	))
	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
	}
	if env.sms.last(t) == first {
		t.Error("resend did not rotate the code")
	}

	// Switch to email and complete with the email code.
	w = postJSON(env.testEnv, PathLoginAction, fmt.Sprintf(
		`{"handle":%q,"action":"resend","channel":"email"}`, res.Handle,
	))
	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d", w.Code, http.StatusOK)
	}
	w = postJSON(env.testEnv, PathLoginContinue, fmt.Sprintf(
		`{"handle":%q,"code":%q}`, res.Handle, env.email.last(t),
	))
	if w.Code != http.StatusNoContent {
		t.Fatalf("got status %d; want %d", w.Code, http.StatusNoContent)
	}
}

func TestFlowAction_UnknownChannel(t *testing.T) {
	t.Parallel()
	env := newFlowEnv(t)
	res := env.login(t, false)

	w := postJSON(env.testEnv, PathLoginAction, fmt.Sprintf(
		`{"handle":%q,"action":"resend","channel":"carrier-pigeon"}`, res.Handle,
	))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d; want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRememberMe_TrustsDeviceAndSkips(t *testing.T) {
	t.Parallel()
	env := newFlowEnv(t)

	// First login with remember: complete the OTP step.
	res := env.login(t, true)
	w := postJSON(env.testEnv, PathLoginContinue, fmt.Sprintf(
		`{"handle":%q,"code":%q}`, res.Handle, env.sms.last(t),
	))
	if w.Code != http.StatusNoContent {
		t.Fatalf("got status %d; want %d", w.Code, http.StatusNoContent)
	}

	// The remembered session persists, and a trust cookie is set.
	if sc := sessionCookie(w); sc == nil || sc.MaxAge <= 0 {
		t.Fatalf("remembered session should be a persistent cookie: %+v", sc)
	}
	tc := trustCookie(w)
	if tc == nil || tc.Value == "" {
		t.Fatal("missing device trust cookie")
	}

	delivered := len(env.sms.codes)

	// A second login on the trusted device skips the OTP step entirely.
	w = postJSON(env.testEnv, PathLogin,
		`{"username":"alice","password":"wonderland"}`, tc,
	)
	if w.Code != http.StatusNoContent {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusNoContent, w.Body)
	}
	if sessionCookie(w) == nil {
		t.Error("missing session cookie on trusted-device login")
	}
	if len(env.sms.codes) != delivered {
		t.Error("a trusted device should not trigger a new code")
	}
}

func TestFlowEndpoints_AbsentWithoutFlow(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	w := postJSON(env, PathLoginContinue, `{"handle":"x","code":"123456"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("got status %d; want %d", w.Code, http.StatusNotFound)
	}
}

func TestPasswordless_Login(t *testing.T) {
	t.Parallel()
	env := newFlowEnv(t, WithPasswordless())

	// Identify by username alone; the flow's OTP factor authenticates.
	w := postJSON(env.testEnv, PathLoginIdentify, `{"username":"alice"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("identify: got %d; want 200: %s", w.Code, w.Body)
	}
	if sessionCookie(w) != nil {
		t.Fatal("no session before the flow completes")
	}
	res := decodeJSON[FlowResponse](t, w)
	if res.Step != "otp" {
		t.Fatalf("got step %q; want otp", res.Step)
	}
	if len(env.sms.codes) != 1 {
		t.Fatalf("got %d codes; want 1", len(env.sms.codes))
	}

	w = postJSON(env.testEnv, PathLoginContinue, fmt.Sprintf(
		`{"handle":%q,"code":%q}`, res.Handle, env.sms.last(t),
	))
	if w.Code != http.StatusNoContent {
		t.Fatalf("continue: got %d; want 204: %s", w.Code, w.Body)
	}
	if sessionCookie(w) == nil {
		t.Error("missing session cookie after passwordless login")
	}
}

func TestPasswordless_UnknownUser(t *testing.T) {
	t.Parallel()
	env := newFlowEnv(t, WithPasswordless())

	w := postJSON(env.testEnv, PathLoginIdentify, `{"username":"nobody"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d; want %d", w.Code, http.StatusUnauthorized)
	}
	if len(env.sms.codes) != 0 {
		t.Error("no code should be delivered for an unknown username")
	}
}

func TestPasswordless_AbsentWithoutOptIn(t *testing.T) {
	t.Parallel()
	env := newFlowEnv(t) // WithFlow but not WithPasswordless

	w := postJSON(env.testEnv, PathLoginIdentify, `{"username":"alice"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d; want %d", w.Code, http.StatusNotFound)
	}
}

func TestPasswordless_RefusesZeroFactor(t *testing.T) {
	t.Parallel()
	// A planner that yields no factors must never authenticate on a username
	// alone.
	empty := func(
		_ context.Context, _ Subject, _ trust.Device, _ Steps,
	) ([]flow.Step, error) {
		return nil, nil
	}
	env := newTestEnv(t, WithFlow(empty), WithPasswordless())

	w := postJSON(env, PathLoginIdentify, `{"username":"alice"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("got %d; want %d", w.Code, http.StatusInternalServerError)
	}
	if len(env.subjects.sessions) != 0 {
		t.Error("a zero-factor passwordless login must not create a session")
	}
}

func TestFlowThrottle_LocksOutPerHandle(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_752_000_000, 0)
	env := newFlowEnv(t,
		withThrottle(throttle.New(throttle.Config{
			Rate:  rate.Limit(1),
			Burst: 10,
			Clock: func() time.Time { return now },
		})),
		withThrottlePenalty(5),
	)
	res := env.login(t, false)

	guess := func() int {
		return postJSON(env.testEnv, PathLoginContinue, fmt.Sprintf(
			`{"handle":%q,"code":"000000"}`, res.Handle,
		)).Code
	}
	for i := range 2 {
		if code := guess(); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d; want %d", i, code, http.StatusUnauthorized)
		}
	}
	if code := guess(); code != http.StatusTooManyRequests {
		t.Fatalf("got %d; want %d", code, http.StatusTooManyRequests)
	}
}
