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
	"bytes"
	"context"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"uuid"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/iam/artifact"
	"github.com/deep-rent/nexus/sec/iam/flow"
	"github.com/deep-rent/nexus/sec/iam/idp"
	"github.com/deep-rent/nexus/sec/iam/oauth"
	"github.com/deep-rent/nexus/sec/iam/otp"
	"github.com/deep-rent/nexus/sec/iam/passkey"
	"github.com/deep-rent/nexus/sec/iam/session"
	"github.com/deep-rent/nexus/sec/iam/trust"
	"github.com/deep-rent/nexus/sys/log"
)

// fakeClient is a configurable in-memory [oauth.Client] implementation.
type fakeClient struct {
	id        uuid.UUID
	public    bool
	secret    string
	audience  []string
	redirects []string
	grants    []oauth.GrantType
	scopes    []string
}

func (c *fakeClient) ID() uuid.UUID      { return c.id }
func (c *fakeClient) Public() bool       { return c.public }
func (c *fakeClient) Audience() []string { return c.audience }

func (c *fakeClient) VerifySecret(secret string) bool {
	return c.secret != "" && secret == c.secret
}

func (c *fakeClient) VerifyRedirectURI(uri string) bool {
	return oauth.VerifyRedirectURI(uri, c.redirects)
}

func (c *fakeClient) CanUseGrant(grant oauth.GrantType) bool {
	return slices.Contains(c.grants, grant)
}

func (c *fakeClient) CanUseScope(scope string) bool {
	return slices.Contains(c.scopes, scope)
}

var _ oauth.Client = (*fakeClient)(nil)

// fakeClientStore is an in-memory [oauth.ClientStore].
type fakeClientStore struct {
	clients map[uuid.UUID]oauth.Client
	err     error
}

func (s *fakeClientStore) GetClient(
	_ context.Context,
	id uuid.UUID,
) (oauth.Client, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.clients[id], nil
}

var _ oauth.ClientStore = (*fakeClientStore)(nil)

// fakeSubject is a minimal [Subject] implementation.
type fakeSubject struct {
	id       uuid.UUID
	username string
	roles    []string
}

func (s *fakeSubject) ID() uuid.UUID    { return s.id }
func (s *fakeSubject) Username() string { return s.username }
func (s *fakeSubject) Roles() []string  { return s.roles }

var _ Subject = (*fakeSubject)(nil)

// fakeSubjectStore is an in-memory [SubjectStore].
type fakeSubjectStore struct {
	subjects  map[uuid.UUID]*fakeSubject
	passwords map[string]string    // username -> password
	usernames map[string]uuid.UUID // username -> subject ID
	external  map[string]uuid.UUID // provider "/" external ID -> subject ID
	err       error
}

func newFakeSubjectStore() *fakeSubjectStore {
	return &fakeSubjectStore{
		subjects:  make(map[uuid.UUID]*fakeSubject),
		passwords: make(map[string]string),
		usernames: make(map[string]uuid.UUID),
		external:  make(map[string]uuid.UUID),
	}
}

func (s *fakeSubjectStore) Authenticate(
	_ context.Context,
	username, password string,
) (Subject, error) {
	if s.err != nil {
		return nil, s.err
	}
	if pw, ok := s.passwords[username]; !ok || pw != password {
		return nil, nil
	}
	if sub, ok := s.subjects[s.usernames[username]]; ok {
		return sub, nil
	}
	return nil, nil
}

func (s *fakeSubjectStore) GetSubject(
	_ context.Context,
	id uuid.UUID,
) (Subject, error) {
	if s.err != nil {
		return nil, s.err
	}
	if sub, ok := s.subjects[id]; ok {
		return sub, nil
	}
	return nil, nil
}

func (s *fakeSubjectStore) GetSubjectByUsername(
	_ context.Context,
	username string,
) (Subject, error) {
	if s.err != nil {
		return nil, s.err
	}
	if sub, ok := s.subjects[s.usernames[username]]; ok {
		return sub, nil
	}
	return nil, nil
}

func (s *fakeSubjectStore) GetSubjectByExternalID(
	_ context.Context,
	provider string,
	identity idp.Claimant,
) (Subject, error) {
	if s.err != nil {
		return nil, s.err
	}
	id, ok := s.external[provider+"/"+identity.Subject]
	if !ok {
		return nil, nil
	}
	if sub, ok := s.subjects[id]; ok {
		return sub, nil
	}
	return nil, nil
}

var _ SubjectStore = (*fakeSubjectStore)(nil)

// fakeDeviceCodeStore is an in-memory [oauth.DeviceCodeStore]: an
// [artifact.Map] extended by the user-code lookup and the poll timestamp
// update.
type fakeDeviceCodeStore struct {
	*artifact.Map[oauth.Digest, oauth.DeviceCode]
}

func (s *fakeDeviceCodeStore) GetByUserCode(
	ctx context.Context,
	userCode oauth.Digest,
) (oauth.DeviceCode, bool, error) {
	if s.Err != nil {
		return oauth.DeviceCode{}, false, s.Err
	}
	var (
		match oauth.DeviceCode
		found bool
	)
	s.Range(func(_ oauth.Digest, c oauth.DeviceCode) bool {
		if c.UserCode == userCode {
			match, found = c, true
			return false
		}
		return true
	})
	return match, found, nil
}

func (s *fakeDeviceCodeStore) Touch(
	ctx context.Context,
	code oauth.Digest,
	lastPolledAt int64,
) error {
	c, found, err := s.Get(ctx, code)
	if err != nil || !found {
		return err
	}
	c.LastPolledAt = lastPolledAt
	return s.Update(ctx, c)
}

var _ oauth.DeviceCodeStore = (*fakeDeviceCodeStore)(nil)

// fakeTrustStore is an in-memory [trust.Store]: an [artifact.Map] extended by
// the owner-scoped bulk deletion.
type fakeTrustStore struct {
	*artifact.Map[string, trust.Record]
}

func (s *fakeTrustStore) DeleteForOwner(
	ctx context.Context,
	owner string,
) error {
	if s.Err != nil {
		return s.Err
	}
	s.Range(func(id string, r trust.Record) bool {
		if r.Owner == owner {
			_, _ = s.Delete(ctx, id)
		}
		return true
	})
	return nil
}

var _ trust.Store = (*fakeTrustStore)(nil)

// fakeCredentialStore is an in-memory [passkey.CredentialStore].
type fakeCredentialStore struct {
	mu    sync.Mutex
	creds map[string][]passkey.Credential
	err   error
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
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.creds[owner] {
		if bytes.Equal(c.ID, cred.ID) {
			s.creds[owner][i] = cred
		}
	}
	return nil
}

var _ passkey.CredentialStore = (*fakeCredentialStore)(nil)

// fakeStores bundles Map-backed [Stores] with typed handles for seeding and
// peeking.
type fakeStores struct {
	Stores
	authCodes     *artifact.Map[oauth.Digest, oauth.AuthCode]
	refreshTokens *artifact.Map[oauth.Digest, oauth.RefreshToken]
	deviceCodes   *fakeDeviceCodeStore
	sessions      *artifact.Map[string, session.Record]
	challenges    *artifact.Map[string, otp.Challenge]
	flows         *artifact.Map[string, flow.Transaction]
	trust         *fakeTrustStore
	ceremonies    *artifact.Map[string, passkey.Ceremony]
	credentials   *fakeCredentialStore
}

func newFakeStores() *fakeStores {
	s := &fakeStores{
		authCodes: artifact.NewMap(
			func(c oauth.AuthCode) oauth.Digest { return c.Code },
		),
		refreshTokens: artifact.NewMap(
			func(r oauth.RefreshToken) oauth.Digest { return r.Token },
		),
		deviceCodes: &fakeDeviceCodeStore{Map: artifact.NewMap(
			func(c oauth.DeviceCode) oauth.Digest { return c.DeviceCode },
		)},
		sessions: artifact.NewMap(
			func(r session.Record) string { return r.ID },
		),
		challenges: artifact.NewMap(
			func(c otp.Challenge) string { return c.ID },
		),
		flows: artifact.NewMap(
			func(t flow.Transaction) string { return t.ID },
		),
		trust: &fakeTrustStore{Map: artifact.NewMap(
			func(r trust.Record) string { return r.ID },
		)},
		ceremonies: artifact.NewMap(
			func(c passkey.Ceremony) string { return c.ID },
		),
		credentials: newFakeCredentialStore(),
	}
	s.Stores = Stores{
		AuthCodes:     s.authCodes,
		RefreshTokens: s.refreshTokens,
		DeviceCodes:   s.deviceCodes,
		Sessions:      s.sessions,
		Challenges:    s.challenges,
		Flows:         s.flows,
		Trust:         s.trust,
		Ceremonies:    s.ceremonies,
		Credentials:   s.credentials,
	}
	return s
}

// setErr makes every store fail with the given error, emulating a datastore
// outage.
func (s *fakeStores) setErr(err error) {
	s.authCodes.Err = err
	s.refreshTokens.Err = err
	s.deviceCodes.Err = err
	s.sessions.Err = err
	s.challenges.Err = err
	s.flows.Err = err
	s.trust.Err = err
	s.ceremonies.Err = err
	s.credentials.err = err
}

// seed inserts a record into the store, failing the test on error.
func seed[K ~string, V any](t *testing.T, s artifact.Store[K, V], v V) {
	t.Helper()
	if err := s.Create(t.Context(), v); err != nil {
		t.Fatalf("failed to seed store: %v", err)
	}
}

// seedSession stores a resolvable session under the given raw key for the
// subject, mirroring what the session engine would persist. It panics on a
// storage fault, which only a test-injected error can cause.
func seedSession(s *fakeStores, key string, id uuid.UUID, expiresAt int64) {
	err := s.sessions.Create(context.Background(), session.Record{
		ID:        digest.DefaultHasher.String(key),
		Owner:     id.String(),
		ExpiresAt: expiresAt,
	})
	if err != nil {
		panic(err)
	}
}

// sessionOwner resolves the subject a raw session key maps to, reporting
// whether the session exists.
func sessionOwner(
	t *testing.T,
	s *fakeStores,
	key string,
) (uuid.UUID, bool) {
	t.Helper()
	r, found, err := s.sessions.Get(
		t.Context(),
		digest.DefaultHasher.String(key),
	)
	if err != nil {
		t.Fatalf("failed to read session: %v", err)
	}
	if !found {
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(r.Owner)
	if err != nil {
		t.Fatalf("malformed session owner %q: %v", r.Owner, err)
	}
	return id, true
}

// listCreds returns the credentials stored for the subject, failing the test
// on a storage error.
func listCreds(
	t *testing.T,
	s *fakeCredentialStore,
	id uuid.UUID,
) []passkey.Credential {
	t.Helper()
	creds, err := s.List(t.Context(), id.String())
	if err != nil {
		t.Fatalf("failed to list credentials: %v", err)
	}
	return creds
}

// discardLogger returns a logger that drops all records.
func discardLogger() *log.Logger {
	return log.Discard()
}

// newProposal assembles an [oauth.Proposal] for direct grant testing.
func newProposal(
	c oauth.Client,
	tokens oauth.TokenStores,
	data url.Values,
	now time.Time,
) *oauth.Proposal {
	return oauth.NewProposal(
		c,
		tokens,
		data,
		nil,
		discardLogger(),
		func() time.Time { return now },
	)
}

// errCode extracts the OAuth error code from an error returned by a grant,
// or an empty string if the error is nil or not an [*oauth.Error].
func errCode(err error) string {
	if e, ok := err.(*oauth.Error); ok {
		return e.Code
	}
	return ""
}

// newDigest fingerprints v with the default hasher, mirroring the server's
// default configuration.
func newDigest(v string) oauth.Digest {
	return oauth.Digest(digest.DefaultHasher.String(v))
}
