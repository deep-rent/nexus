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

package passkey_test

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"slices"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/deep-rent/nexus/sec/iam/artifact"
	"github.com/deep-rent/nexus/sec/iam/passkey"
	"github.com/deep-rent/nexus/std/clock"
)

const (
	testRPID     = "example.com"
	testRPName   = "Example"
	testRPOrigin = "https://app.example.com"
)

// fakeCredentialStore is an in-memory [passkey.CredentialStore].
type fakeCredentialStore struct {
	creds   map[string][]passkey.Credential
	updates int
	err     error
}

func newFakeCredentialStore() *fakeCredentialStore {
	return &fakeCredentialStore{creds: make(map[string][]passkey.Credential)}
}

func (s *fakeCredentialStore) List(
	_ context.Context,
	owner string,
) ([]passkey.Credential, error) {
	if s.err != nil {
		return nil, s.err
	}
	return slices.Clone(s.creds[owner]), nil
}

func (s *fakeCredentialStore) Create(
	_ context.Context,
	owner, _ string,
	cred passkey.Credential,
) error {
	if s.err != nil {
		return s.err
	}
	s.creds[owner] = append(s.creds[owner], cred)
	return nil
}

func (s *fakeCredentialStore) Update(
	_ context.Context,
	owner string,
	cred passkey.Credential,
) error {
	if s.err != nil {
		return s.err
	}
	for i, c := range s.creds[owner] {
		if bytes.Equal(c.ID, cred.ID) {
			s.creds[owner][i] = cred
			s.updates++
		}
	}
	return nil
}

var _ passkey.CredentialStore = (*fakeCredentialStore)(nil)

// fakeDirectory resolves accounts by their user handle from the credential
// store.
type fakeDirectory struct {
	accounts map[string]passkey.Account // string(handle) -> account
	creds    *fakeCredentialStore
	err      error
}

func (d *fakeDirectory) Lookup(
	ctx context.Context,
	userHandle []byte,
) (passkey.Account, bool, error) {
	if d.err != nil {
		return passkey.Account{}, false, d.err
	}
	acct, ok := d.accounts[string(userHandle)]
	if !ok {
		return passkey.Account{}, false, nil
	}
	creds, err := d.creds.List(ctx, acct.Owner)
	if err != nil {
		return passkey.Account{}, false, err
	}
	acct.Credentials = creds
	return acct, true, nil
}

// env bundles a relying party with its stores, a controllable clock, and a
// virtual authenticator producing real attestations and assertions.
type env struct {
	party         *passkey.RelyingParty
	store         *artifact.Map[string, passkey.Ceremony]
	creds         *fakeCredentialStore
	directory     *fakeDirectory
	acct          passkey.Account
	rp            virtualwebauthn.RelyingParty
	authenticator virtualwebauthn.Authenticator
	cred          virtualwebauthn.Credential
	now           time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()

	handle := []byte("user-handle-0001")
	e := &env{
		store: artifact.NewMap(
			func(c passkey.Ceremony) string { return c.ID },
		),
		creds: newFakeCredentialStore(),
		acct: passkey.Account{
			Handle:   handle,
			Owner:    "alice",
			Username: "alice@example.com",
		},
		rp: virtualwebauthn.RelyingParty{
			ID:     testRPID,
			Name:   testRPName,
			Origin: testRPOrigin,
		},
		cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
		now:  time.Unix(1_752_000_000, 0),
	}
	e.directory = &fakeDirectory{
		accounts: map[string]passkey.Account{string(handle): e.acct},
		creds:    e.creds,
	}
	e.authenticator = virtualwebauthn.NewAuthenticatorWithOptions(
		virtualwebauthn.AuthenticatorOptions{UserHandle: handle},
	)
	e.party = passkey.New(
		passkey.Config{
			RPID:          testRPID,
			RPDisplayName: testRPName,
			RPOrigins:     []string{testRPOrigin},
		},
		e.store,
		e.creds,
		e.directory,
		passkey.WithClock(clock.Clock(func() time.Time { return e.now })),
	)
	return e
}

// register runs a complete registration ceremony and arms the virtual
// authenticator with the resulting credential.
func (e *env) register(t *testing.T) {
	t.Helper()

	handle, options, expiresIn, err := e.party.BeginRegistration(
		t.Context(),
		e.acct,
	)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if expiresIn != int64(passkey.DefaultLifetime.Seconds()) {
		t.Errorf("got expiresIn %d; want the default lifetime", expiresIn)
	}

	opts, err := virtualwebauthn.ParseAttestationOptions(marshal(t, options))
	if err != nil {
		t.Fatalf("failed to parse attestation options: %v", err)
	}
	attestation := virtualwebauthn.CreateAttestationResponse(
		e.rp, e.authenticator, e.cred, *opts,
	)

	out, err := e.party.FinishRegistration(
		t.Context(), e.acct, "test key", handle, []byte(attestation),
	)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	if !out.OK() {
		t.Fatalf("got outcome %+v; want OK (reason: %v)", out, out.Reason)
	}
	e.authenticator.AddCredential(e.cred)
}

// assert answers the given login options with the virtual authenticator.
func (e *env) assert(t *testing.T, options any) []byte {
	t.Helper()

	opts, err := virtualwebauthn.ParseAssertionOptions(marshal(t, options))
	if err != nil {
		t.Fatalf("failed to parse assertion options: %v", err)
	}
	return []byte(virtualwebauthn.CreateAssertionResponse(
		e.rp, e.authenticator, e.cred, *opts,
	))
}

func marshal(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal options: %v", err)
	}
	return string(raw)
}

func TestRelyingParty_RegisterAndLogin(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.register(t)

	// The credential was persisted for the owner.
	creds, err := e.creds.List(t.Context(), "alice")
	if err != nil || len(creds) != 1 {
		t.Fatalf("got %d stored credentials (err %v); want 1", len(creds), err)
	}

	// A discoverable login resolves the account from the assertion.
	handle, options, _, err := e.party.BeginLogin(t.Context())
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	out, err := e.party.FinishLogin(t.Context(), handle, e.assert(t, options))
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if !out.OK() || out.Owner != "alice" {
		t.Fatalf("got outcome %+v; want OK owner=alice", out)
	}

	// All ceremony state is consumed.
	if e.store.Len() != 0 {
		t.Errorf("got %d pending ceremonies; want 0", e.store.Len())
	}
}

func TestRelyingParty_FinishLogin_SingleUse(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.register(t)

	handle, options, _, err := e.party.BeginLogin(t.Context())
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	response := e.assert(t, options)

	if out, _ := e.party.FinishLogin(t.Context(), handle, response); !out.OK() {
		t.Fatalf("first finish should succeed; got %+v", out)
	}
	if out, _ := e.party.FinishLogin(
		t.Context(),
		handle,
		response,
	); out.Status != passkey.StatusInvalid {
		t.Fatalf("replay should be invalid; got %+v", out)
	}
}

func TestRelyingParty_FinishLogin_Expired(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.register(t)

	handle, options, _, err := e.party.BeginLogin(t.Context())
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	response := e.assert(t, options)

	e.now = e.now.Add(passkey.DefaultLifetime + time.Second)

	out, err := e.party.FinishLogin(t.Context(), handle, response)
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if out.Status != passkey.StatusInvalid {
		t.Fatalf("expired ceremony should be invalid; got %+v", out)
	}
}

func TestRelyingParty_FinishLogin_GarbageAssertion(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.register(t)

	handle, _, _, err := e.party.BeginLogin(t.Context())
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	out, err := e.party.FinishLogin(
		t.Context(), handle, []byte("not an assertion"),
	)
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if out.Status != passkey.StatusRejected || out.Reason == nil {
		t.Fatalf("got %+v; want rejected with a reason", out)
	}

	// The failed attempt burned the ceremony.
	if out, _ := e.party.FinishLogin(
		t.Context(),
		handle,
		[]byte("x"),
	); out.Status != passkey.StatusInvalid {
		t.Fatalf("burned ceremony should be invalid; got %+v", out)
	}
}

func TestRelyingParty_FinishRegistration_WrongOwner(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	handle, options, _, err := e.party.BeginRegistration(t.Context(), e.acct)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	opts, err := virtualwebauthn.ParseAttestationOptions(marshal(t, options))
	if err != nil {
		t.Fatalf("failed to parse attestation options: %v", err)
	}
	attestation := virtualwebauthn.CreateAttestationResponse(
		e.rp, e.authenticator, e.cred, *opts,
	)

	// A ceremony begun for one account cannot be finished by another.
	mallory := passkey.Account{
		Handle:   []byte("mallory-handle-1"),
		Owner:    "mallory",
		Username: "mallory@example.com",
	}
	out, err := e.party.FinishRegistration(
		t.Context(), mallory, "", handle, []byte(attestation),
	)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	if out.Status != passkey.StatusInvalid {
		t.Fatalf("got %+v; want invalid for a foreign ceremony", out)
	}
}

func TestRelyingParty_StartLogin_CallerHandle(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.register(t)

	// The caller keys the ceremony on its own high-entropy handle, as the
	// login flow step does.
	const handle = "outer-flow-handle:passkey"
	options, expiresIn, err := e.party.StartLogin(t.Context(), handle)
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	if expiresIn <= 0 {
		t.Errorf("got expiresIn %d; want > 0", expiresIn)
	}

	out, err := e.party.FinishLogin(t.Context(), handle, e.assert(t, options))
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if !out.OK() || out.Owner != "alice" {
		t.Fatalf("got %+v; want OK owner=alice", out)
	}
}

func TestRelyingParty_LoginUpdatesCredential(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.register(t)

	handle, options, _, err := e.party.BeginLogin(t.Context())
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	out, err := e.party.FinishLogin(t.Context(), handle, e.assert(t, options))
	if err != nil || !out.OK() {
		t.Fatalf("FinishLogin: %+v (%v)", out, err)
	}

	// The verified record (signature counter and backup flags) must be
	// persisted after every assertion, since future clone detection is
	// validated against it.
	if e.creds.updates != 1 {
		t.Errorf("got %d credential updates; want 1", e.creds.updates)
	}
}

func TestNew_Panics(t *testing.T) {
	t.Parallel()

	cfg := passkey.Config{
		RPID:          testRPID,
		RPDisplayName: testRPName,
		RPOrigins:     []string{testRPOrigin},
	}
	store := artifact.NewMap(func(c passkey.Ceremony) string { return c.ID })
	creds := newFakeCredentialStore()
	dir := &fakeDirectory{creds: creds}

	tests := []struct {
		name string
		fn   func()
	}{
		{"nil store", func() { passkey.New(cfg, nil, creds, dir) }},
		{"nil credentials", func() { passkey.New(cfg, store, nil, dir) }},
		{"nil directory", func() { passkey.New(cfg, store, creds, nil) }},
		{"invalid config", func() {
			passkey.New(passkey.Config{}, store, creds, dir)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Error("New did not panic")
				}
			}()
			tt.fn()
		})
	}
}
