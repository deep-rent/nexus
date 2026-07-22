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
	"log/slog"
	"net/url"
	"slices"
	"time"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/iam/idp"
	"github.com/deep-rent/nexus/sec/iam/oauth"
	"uuid"
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
	sessions  map[string]uuid.UUID // session key -> subject ID
	// credentials maps subject IDs to registered passkey credentials.
	credentials map[uuid.UUID][]WebAuthnCredential
	err         error
}

func newFakeSubjectStore() *fakeSubjectStore {
	return &fakeSubjectStore{
		subjects:  make(map[uuid.UUID]*fakeSubject),
		passwords: make(map[string]string),
		usernames: make(map[string]uuid.UUID),
		external:  make(map[string]uuid.UUID),
		sessions:  make(map[string]uuid.UUID),
		credentials: make(
			map[uuid.UUID][]WebAuthnCredential,
		),
	}
}

func (s *fakeSubjectStore) GetWebAuthnCredentials(
	_ context.Context,
	subjectID uuid.UUID,
) ([]WebAuthnCredential, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.credentials[subjectID], nil
}

func (s *fakeSubjectStore) CreateWebAuthnCredential(
	_ context.Context,
	subjectID uuid.UUID,
	_ string,
	credential WebAuthnCredential,
) error {
	if s.err != nil {
		return s.err
	}
	s.credentials[subjectID] = append(s.credentials[subjectID], credential)
	return nil
}

func (s *fakeSubjectStore) UpdateWebAuthnCredential(
	_ context.Context,
	subjectID uuid.UUID,
	credential WebAuthnCredential,
) error {
	if s.err != nil {
		return s.err
	}
	for i, c := range s.credentials[subjectID] {
		if bytes.Equal(c.ID, credential.ID) {
			s.credentials[subjectID][i] = credential
		}
	}
	return nil
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

func (s *fakeSubjectStore) GetSubjectBySession(
	_ context.Context,
	key string,
) (Subject, error) {
	if s.err != nil {
		return nil, s.err
	}
	id, ok := s.sessions[key]
	if !ok {
		return nil, nil
	}
	if sub, ok := s.subjects[id]; ok {
		return sub, nil
	}
	return nil, nil
}

func (s *fakeSubjectStore) CreateSession(
	_ context.Context,
	key string,
	subjectID uuid.UUID,
) error {
	if s.err != nil {
		return s.err
	}
	s.sessions[key] = subjectID
	return nil
}

func (s *fakeSubjectStore) DeleteSession(_ context.Context, key string) error {
	if s.err != nil {
		return s.err
	}
	delete(s.sessions, key)
	return nil
}

var _ SubjectStore = (*fakeSubjectStore)(nil)

// fakeSessionStore is an in-memory [SessionStore].
type fakeSessionStore struct {
	authCodes     map[oauth.Digest]oauth.AuthCode
	refreshTokens map[oauth.Digest]oauth.RefreshToken
	deviceCodes   map[oauth.Digest]oauth.DeviceCode
	otpChallenges map[oauth.Digest]OTPChallenge
	// webAuthnSessions maps handle digests to pending ceremony sessions.
	webAuthnSessions map[oauth.Digest]WebAuthnSession
	// trustedDevices maps token digests to remember-me device trust records.
	trustedDevices map[oauth.Digest]TrustedDevice
	// flowTransactions maps handle digests to in-progress login flows.
	flowTransactions map[oauth.Digest]FlowTransaction
	err              error
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{
		authCodes:     make(map[oauth.Digest]oauth.AuthCode),
		refreshTokens: make(map[oauth.Digest]oauth.RefreshToken),
		deviceCodes:   make(map[oauth.Digest]oauth.DeviceCode),
		otpChallenges: make(map[oauth.Digest]OTPChallenge),
		webAuthnSessions: make(
			map[oauth.Digest]WebAuthnSession,
		),
		trustedDevices:   make(map[oauth.Digest]TrustedDevice),
		flowTransactions: make(map[oauth.Digest]FlowTransaction),
	}
}

func (s *fakeSessionStore) GetFlowTransaction(
	_ context.Context,
	handle oauth.Digest,
) (FlowTransaction, error) {
	if s.err != nil {
		return FlowTransaction{}, s.err
	}
	return s.flowTransactions[handle], nil
}

func (s *fakeSessionStore) CreateFlowTransaction(
	_ context.Context,
	data FlowTransaction,
) error {
	if s.err != nil {
		return s.err
	}
	s.flowTransactions[data.Handle] = data
	return nil
}

func (s *fakeSessionStore) UpdateFlowTransaction(
	_ context.Context,
	data FlowTransaction,
) error {
	if s.err != nil {
		return s.err
	}
	s.flowTransactions[data.Handle] = data
	return nil
}

func (s *fakeSessionStore) DeleteFlowTransaction(
	_ context.Context,
	handle oauth.Digest,
) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	_, ok := s.flowTransactions[handle]
	delete(s.flowTransactions, handle)
	return ok, nil
}

func (s *fakeSessionStore) GetTrustedDevice(
	_ context.Context,
	token oauth.Digest,
) (TrustedDevice, error) {
	if s.err != nil {
		return TrustedDevice{}, s.err
	}
	return s.trustedDevices[token], nil
}

func (s *fakeSessionStore) CreateTrustedDevice(
	_ context.Context,
	data TrustedDevice,
) error {
	if s.err != nil {
		return s.err
	}
	s.trustedDevices[data.Token] = data
	return nil
}

func (s *fakeSessionStore) DeleteTrustedDevice(
	_ context.Context,
	token oauth.Digest,
) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	_, ok := s.trustedDevices[token]
	delete(s.trustedDevices, token)
	return ok, nil
}

func (s *fakeSessionStore) DeleteTrustedDevicesForSubject(
	_ context.Context,
	subjectID uuid.UUID,
) error {
	if s.err != nil {
		return s.err
	}
	for k, v := range s.trustedDevices {
		if v.SubjectID == subjectID {
			delete(s.trustedDevices, k)
		}
	}
	return nil
}

func (s *fakeSessionStore) GetWebAuthnSession(
	_ context.Context,
	handle oauth.Digest,
) (WebAuthnSession, error) {
	if s.err != nil {
		return WebAuthnSession{}, s.err
	}
	return s.webAuthnSessions[handle], nil
}

func (s *fakeSessionStore) CreateWebAuthnSession(
	_ context.Context,
	data WebAuthnSession,
) error {
	if s.err != nil {
		return s.err
	}
	s.webAuthnSessions[data.Handle] = data
	return nil
}

func (s *fakeSessionStore) DeleteWebAuthnSession(
	_ context.Context,
	handle oauth.Digest,
) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	_, ok := s.webAuthnSessions[handle]
	delete(s.webAuthnSessions, handle)
	return ok, nil
}

func (s *fakeSessionStore) GetAuthCode(
	_ context.Context,
	code oauth.Digest,
) (oauth.AuthCode, error) {
	if s.err != nil {
		return oauth.AuthCode{}, s.err
	}
	return s.authCodes[code], nil
}

func (s *fakeSessionStore) CreateAuthCode(
	_ context.Context,
	data oauth.AuthCode,
) error {
	if s.err != nil {
		return s.err
	}
	s.authCodes[data.Code] = data
	return nil
}

func (s *fakeSessionStore) DeleteAuthCode(
	_ context.Context,
	code oauth.Digest,
) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	_, ok := s.authCodes[code]
	delete(s.authCodes, code)
	return ok, nil
}

func (s *fakeSessionStore) GetRefreshToken(
	_ context.Context,
	token oauth.Digest,
) (oauth.RefreshToken, error) {
	if s.err != nil {
		return oauth.RefreshToken{}, s.err
	}
	return s.refreshTokens[token], nil
}

func (s *fakeSessionStore) CreateRefreshToken(
	_ context.Context,
	data oauth.RefreshToken,
) error {
	if s.err != nil {
		return s.err
	}
	s.refreshTokens[data.Token] = data
	return nil
}

func (s *fakeSessionStore) DeleteRefreshToken(
	_ context.Context,
	token oauth.Digest,
) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	_, ok := s.refreshTokens[token]
	delete(s.refreshTokens, token)
	return ok, nil
}

func (s *fakeSessionStore) GetDeviceCode(
	_ context.Context,
	code oauth.Digest,
) (oauth.DeviceCode, error) {
	if s.err != nil {
		return oauth.DeviceCode{}, s.err
	}
	return s.deviceCodes[code], nil
}

func (s *fakeSessionStore) GetDeviceCodeByUserCode(
	_ context.Context,
	userCode oauth.Digest,
) (oauth.DeviceCode, error) {
	if s.err != nil {
		return oauth.DeviceCode{}, s.err
	}
	for _, c := range s.deviceCodes {
		if c.UserCode == userCode {
			return c, nil
		}
	}
	return oauth.DeviceCode{}, nil
}

func (s *fakeSessionStore) CreateDeviceCode(
	_ context.Context,
	data oauth.DeviceCode,
) error {
	if s.err != nil {
		return s.err
	}
	s.deviceCodes[data.DeviceCode] = data
	return nil
}

func (s *fakeSessionStore) UpdateDeviceCode(
	_ context.Context,
	data oauth.DeviceCode,
) error {
	if s.err != nil {
		return s.err
	}
	s.deviceCodes[data.DeviceCode] = data
	return nil
}

func (s *fakeSessionStore) TouchDeviceCode(
	_ context.Context,
	code oauth.Digest,
	lastPolledAt int64,
) error {
	if s.err != nil {
		return s.err
	}
	if c, ok := s.deviceCodes[code]; ok {
		c.LastPolledAt = lastPolledAt
		s.deviceCodes[code] = c
	}
	return nil
}

func (s *fakeSessionStore) DeleteDeviceCode(
	_ context.Context,
	code oauth.Digest,
) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	_, ok := s.deviceCodes[code]
	delete(s.deviceCodes, code)
	return ok, nil
}

func (s *fakeSessionStore) GetOTPChallenge(
	_ context.Context,
	challenge oauth.Digest,
) (OTPChallenge, error) {
	if s.err != nil {
		return OTPChallenge{}, s.err
	}
	return s.otpChallenges[challenge], nil
}

func (s *fakeSessionStore) CreateOTPChallenge(
	_ context.Context,
	data OTPChallenge,
) error {
	if s.err != nil {
		return s.err
	}
	s.otpChallenges[data.Challenge] = data
	return nil
}

func (s *fakeSessionStore) UpdateOTPChallenge(
	_ context.Context,
	data OTPChallenge,
) error {
	if s.err != nil {
		return s.err
	}
	s.otpChallenges[data.Challenge] = data
	return nil
}

func (s *fakeSessionStore) DeleteOTPChallenge(
	_ context.Context,
	challenge oauth.Digest,
) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	_, ok := s.otpChallenges[challenge]
	delete(s.otpChallenges, challenge)
	return ok, nil
}

var _ SessionStore = (*fakeSessionStore)(nil)

// discardLogger returns a logger that drops all records.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// newProposal assembles an [oauth.Proposal] for direct grant testing.
func newProposal(
	c oauth.Client,
	sessions SessionStore,
	data url.Values,
	now time.Time,
) *oauth.Proposal {
	return oauth.NewProposal(
		c,
		sessions,
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
