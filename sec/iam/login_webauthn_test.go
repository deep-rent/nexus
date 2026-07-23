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
	"encoding/json/jsontext"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"

	"github.com/deep-rent/nexus/sec/iam/flow"
	"github.com/deep-rent/nexus/sec/iam/trust"
)

// registerPasskey enrolls a discoverable credential for the default subject
// using a bearer token, so it works even when password login starts a flow.
func (env *webAuthnEnv) registerPasskey(t *testing.T) {
	t.Helper()
	bearer := "Bearer " + env.mintToken(t)

	req := httptest.NewRequest(
		http.MethodPost, testPrefix+PathWebAuthnRegisterOptions, nil,
	)
	req.Header.Set("Authorization", bearer)
	w := env.do(req)
	if w.Code != http.StatusOK {
		t.Fatalf("register options: got %d; want 200: %s", w.Code, w.Body)
	}
	res := decodeJSON[optionsEnvelope](t, w)
	opts, err := virtualwebauthn.ParseAttestationOptions(string(res.Options))
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}

	attestation := virtualwebauthn.CreateAttestationResponse(
		env.rp, env.authenticator, env.cred, *opts,
	)
	body := fmt.Sprintf(
		`{"handle":%q,"name":"key","credential":%s}`, res.Handle, attestation,
	)
	req = httptest.NewRequest(
		http.MethodPost,
		testPrefix+PathWebAuthnRegister,
		strings.NewReader(body),
	)
	req.Header.Set("Authorization", bearer)
	req.Header.Set("Content-Type", "application/json")
	if w := env.do(req); w.Code != http.StatusNoContent {
		t.Fatalf("register: got %d; want 204: %s", w.Code, w.Body)
	}
	env.authenticator.AddCredential(env.cred)
}

// flowPrompt mirrors [FlowResponse] with the webauthn step prompt kept raw so
// its assertion options can be handed to the virtual authenticator.
type flowPrompt struct {
	Handle string `json:"handle"`
	Step   string `json:"step"`
	Prompt struct {
		Options jsontext.Value `json:"options"`
	} `json:"prompt"`
}

// passkeyPlanner requires a single WebAuthn step after the password.
func passkeyPlanner(
	_ context.Context, _ Subject, _ trust.Device, b Steps,
) ([]flow.Step, error) {
	return []flow.Step{b.WebAuthn("passkey")}, nil
}

// beginPasskeyFlow logs in with the password and returns the WebAuthn prompt.
func (env *webAuthnEnv) beginPasskeyFlow(t *testing.T) flowPrompt {
	t.Helper()
	w := postJSON(
		env.testEnv, PathLogin, `{"username":"alice","password":"wonderland"}`,
	)
	if w.Code != http.StatusOK {
		t.Fatalf("login: got %d; want 200: %s", w.Code, w.Body)
	}
	res := decodeJSON[flowPrompt](t, w)
	if res.Step != "passkey" {
		t.Fatalf("got step %q; want passkey", res.Step)
	}
	return res
}

func TestWebAuthnStep_CompletesFlow(t *testing.T) {
	t.Parallel()
	env := newWebAuthnEnv(t, WithFlow(passkeyPlanner))
	env.registerPasskey(t)

	res := env.beginPasskeyFlow(t)
	opts, err := virtualwebauthn.ParseAssertionOptions(
		string(res.Prompt.Options),
	)
	if err != nil {
		t.Fatalf("parse assertion options: %v", err)
	}
	assertion := virtualwebauthn.CreateAssertionResponse(
		env.rp, env.authenticator, env.cred, *opts,
	)

	w := postJSON(env.testEnv, PathLoginContinue, fmt.Sprintf(
		`{"handle":%q,"credential":%s}`, res.Handle, assertion,
	))
	if w.Code != http.StatusNoContent {
		t.Fatalf("continue: got %d; want 204: %s", w.Code, w.Body)
	}
	if sessionCookie(w) == nil {
		t.Error("missing session cookie after the passkey step")
	}
}

func TestWebAuthnStep_RejectsBadAssertion(t *testing.T) {
	t.Parallel()
	env := newWebAuthnEnv(t, WithFlow(passkeyPlanner))
	env.registerPasskey(t)

	res := env.beginPasskeyFlow(t)

	// A malformed assertion cannot complete the step.
	w := postJSON(env.testEnv, PathLoginContinue, fmt.Sprintf(
		`{"handle":%q,"credential":{"bogus":true}}`, res.Handle,
	))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d; want %d", w.Code, http.StatusUnauthorized)
	}
}
