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
	id    uuid.UUID
	roles []string
}

func (s *fakeSubject) ID() uuid.UUID   { return s.id }
func (s *fakeSubject) Roles() []string { return s.roles }

var _ Subject = (*fakeSubject)(nil)

// fakeSubjectStore is an in-memory [SubjectStore].
type fakeSubjectStore struct {
	subjects  map[uuid.UUID]*fakeSubject
	passwords map[string]string    // username -> password
	usernames map[string]uuid.UUID // username -> subject ID
	external  map[string]uuid.UUID // provider "/" external ID -> subject ID
	sessions  map[string]uuid.UUID // session key -> subject ID
	err       error
}

func newFakeSubjectStore() *fakeSubjectStore {
	return &fakeSubjectStore{
		subjects:  make(map[uuid.UUID]*fakeSubject),
		passwords: make(map[string]string),
		usernames: make(map[string]uuid.UUID),
		external:  make(map[string]uuid.UUID),
		sessions:  make(map[string]uuid.UUID),
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
	authCodes     map[string]AuthCode
	refreshTokens map[string]RefreshToken
	deviceCodes   map[string]DeviceCode
	err           error
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{
		authCodes:     make(map[string]AuthCode),
		refreshTokens: make(map[string]RefreshToken),
		deviceCodes:   make(map[string]DeviceCode),
	}
}

func (s *fakeSessionStore) GetAuthCode(
	_ context.Context,
	code string,
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
	code string,
) error {
	if s.err != nil {
		return s.err
	}
	delete(s.authCodes, code)
	return nil
}

func (s *fakeSessionStore) GetRefreshToken(
	_ context.Context,
	token string,
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
	token string,
) error {
	if s.err != nil {
		return s.err
	}
	delete(s.refreshTokens, token)
	return nil
}

func (s *fakeSessionStore) GetDeviceCode(
	_ context.Context,
	code string,
) (DeviceCode, error) {
	if s.err != nil {
		return DeviceCode{}, s.err
	}
	return s.deviceCodes[code], nil
}

func (s *fakeSessionStore) GetDeviceCodeByUserCode(
	_ context.Context,
	userCode string,
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

func (s *fakeSessionStore) DeleteDeviceCode(
	_ context.Context,
	code string,
) error {
	if s.err != nil {
		return s.err
	}
	delete(s.deviceCodes, code)
	return nil
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
