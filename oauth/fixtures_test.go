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
	"bytes"
	"context"
	"log/slog"
	"net/url"
	"slices"
	"time"

	"uuid"
)

// fakeClient is a configurable in-memory [Client] implementation.
type fakeClient struct {
	id        uuid.UUID
	public    bool
	secret    string
	audience  []string
	redirects []string
	grants    []GrantType
	scopes    []string
}

func (c *fakeClient) ID() uuid.UUID      { return c.id }
func (c *fakeClient) Public() bool       { return c.public }
func (c *fakeClient) Audience() []string { return c.audience }

func (c *fakeClient) VerifySecret(secret string) bool {
	return c.secret != "" && secret == c.secret
}

func (c *fakeClient) VerifyRedirectURI(uri string) bool {
	return VerifyRedirectURI(uri, c.redirects)
}

func (c *fakeClient) CanUseGrant(grant GrantType) bool {
	return slices.Contains(c.grants, grant)
}

func (c *fakeClient) CanUseScope(scope string) bool {
	return slices.Contains(c.scopes, scope)
}

var _ Client = (*fakeClient)(nil)

// fakeClientStore is an in-memory [ClientStore].
type fakeClientStore struct {
	clients map[uuid.UUID]Client
	err     error
}

func (s *fakeClientStore) GetClient(
	_ context.Context,
	id uuid.UUID,
) (Client, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.clients[id], nil
}

var _ ClientStore = (*fakeClientStore)(nil)

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
	identity Claimant,
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
	authCodes     map[Digest]AuthCode
	refreshTokens map[Digest]RefreshToken
	deviceCodes   map[Digest]DeviceCode
	otpChallenges map[Digest]OTPChallenge
	// webAuthnSessions maps handle digests to pending ceremony sessions.
	webAuthnSessions map[Digest]WebAuthnSession
	// trustedDevices maps token digests to remember-me device trust records.
	trustedDevices map[Digest]TrustedDevice
	// flowTransactions maps handle digests to in-progress login flows.
	flowTransactions map[Digest]FlowTransaction
	err              error
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{
		authCodes:     make(map[Digest]AuthCode),
		refreshTokens: make(map[Digest]RefreshToken),
		deviceCodes:   make(map[Digest]DeviceCode),
		otpChallenges: make(map[Digest]OTPChallenge),
		webAuthnSessions: make(
			map[Digest]WebAuthnSession,
		),
		trustedDevices:   make(map[Digest]TrustedDevice),
		flowTransactions: make(map[Digest]FlowTransaction),
	}
}

func (s *fakeSessionStore) GetFlowTransaction(
	_ context.Context,
	handle Digest,
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
	handle Digest,
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
	token Digest,
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
	token Digest,
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
	handle Digest,
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
	handle Digest,
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
	code Digest,
) (AuthCode, error) {
	if s.err != nil {
		return AuthCode{}, s.err
	}
	return s.authCodes[code], nil
}

func (s *fakeSessionStore) CreateAuthCode(
	_ context.Context,
	data AuthCode,
) error {
	if s.err != nil {
		return s.err
	}
	s.authCodes[data.Code] = data
	return nil
}

func (s *fakeSessionStore) DeleteAuthCode(
	_ context.Context,
	code Digest,
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
	token Digest,
) (RefreshToken, error) {
	if s.err != nil {
		return RefreshToken{}, s.err
	}
	return s.refreshTokens[token], nil
}

func (s *fakeSessionStore) CreateRefreshToken(
	_ context.Context,
	data RefreshToken,
) error {
	if s.err != nil {
		return s.err
	}
	s.refreshTokens[data.Token] = data
	return nil
}

func (s *fakeSessionStore) DeleteRefreshToken(
	_ context.Context,
	token Digest,
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
	code Digest,
) (DeviceCode, error) {
	if s.err != nil {
		return DeviceCode{}, s.err
	}
	return s.deviceCodes[code], nil
}

func (s *fakeSessionStore) GetDeviceCodeByUserCode(
	_ context.Context,
	userCode Digest,
) (DeviceCode, error) {
	if s.err != nil {
		return DeviceCode{}, s.err
	}
	for _, c := range s.deviceCodes {
		if c.UserCode == userCode {
			return c, nil
		}
	}
	return DeviceCode{}, nil
}

func (s *fakeSessionStore) CreateDeviceCode(
	_ context.Context,
	data DeviceCode,
) error {
	if s.err != nil {
		return s.err
	}
	s.deviceCodes[data.DeviceCode] = data
	return nil
}

func (s *fakeSessionStore) UpdateDeviceCode(
	_ context.Context,
	data DeviceCode,
) error {
	if s.err != nil {
		return s.err
	}
	s.deviceCodes[data.DeviceCode] = data
	return nil
}

func (s *fakeSessionStore) TouchDeviceCode(
	_ context.Context,
	code Digest,
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
	code Digest,
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
	challenge Digest,
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
	challenge Digest,
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

// newProposal assembles a [Proposal] for direct grant testing.
func newProposal(
	c Client,
	sessions SessionStore,
	data url.Values,
	now time.Time,
) *Proposal {
	return &Proposal{
		Client:   c,
		Sessions: sessions,
		Logger:   discardLogger(),
		Now:      func() time.Time { return now },
		data:     data,
	}
}

// errCode extracts the OAuth error code from an error returned by a grant,
// or an empty string if the error is nil or not an [*Error].
func errCode(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}
