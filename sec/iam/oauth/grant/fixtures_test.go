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

package grant

import (
	"context"
	"log/slog"
	"net/url"
	"slices"
	"time"

	"uuid"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/iam/oauth"
)

// fakeClient is a configurable in-memory [oauth.Client] implementation.
type fakeClient struct {
	id     uuid.UUID
	scopes []string
}

func (c *fakeClient) ID() uuid.UUID      { return c.id }
func (c *fakeClient) Public() bool       { return false }
func (c *fakeClient) Audience() []string { return nil }

func (c *fakeClient) VerifySecret(string) bool      { return false }
func (c *fakeClient) VerifyRedirectURI(string) bool { return false }

func (c *fakeClient) CanUseGrant(oauth.GrantType) bool { return true }

func (c *fakeClient) CanUseScope(scope string) bool {
	return slices.Contains(c.scopes, scope)
}

var _ oauth.Client = (*fakeClient)(nil)

// fakeTokenStore is an in-memory [oauth.TokenStore].
type fakeTokenStore struct {
	authCodes     map[oauth.Digest]oauth.AuthCode
	refreshTokens map[oauth.Digest]oauth.RefreshToken
	deviceCodes   map[oauth.Digest]oauth.DeviceCode
	err           error
}

func newFakeTokenStore() *fakeTokenStore {
	return &fakeTokenStore{
		authCodes:     make(map[oauth.Digest]oauth.AuthCode),
		refreshTokens: make(map[oauth.Digest]oauth.RefreshToken),
		deviceCodes:   make(map[oauth.Digest]oauth.DeviceCode),
	}
}

func (s *fakeTokenStore) GetAuthCode(
	_ context.Context,
	code oauth.Digest,
) (oauth.AuthCode, error) {
	if s.err != nil {
		return oauth.AuthCode{}, s.err
	}
	return s.authCodes[code], nil
}

func (s *fakeTokenStore) CreateAuthCode(
	_ context.Context,
	data oauth.AuthCode,
) error {
	if s.err != nil {
		return s.err
	}
	s.authCodes[data.Code] = data
	return nil
}

func (s *fakeTokenStore) DeleteAuthCode(
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

func (s *fakeTokenStore) GetRefreshToken(
	_ context.Context,
	token oauth.Digest,
) (oauth.RefreshToken, error) {
	if s.err != nil {
		return oauth.RefreshToken{}, s.err
	}
	return s.refreshTokens[token], nil
}

func (s *fakeTokenStore) CreateRefreshToken(
	_ context.Context,
	data oauth.RefreshToken,
) error {
	if s.err != nil {
		return s.err
	}
	s.refreshTokens[data.Token] = data
	return nil
}

func (s *fakeTokenStore) DeleteRefreshToken(
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

func (s *fakeTokenStore) GetDeviceCode(
	_ context.Context,
	code oauth.Digest,
) (oauth.DeviceCode, error) {
	if s.err != nil {
		return oauth.DeviceCode{}, s.err
	}
	return s.deviceCodes[code], nil
}

func (s *fakeTokenStore) GetDeviceCodeByUserCode(
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

func (s *fakeTokenStore) CreateDeviceCode(
	_ context.Context,
	data oauth.DeviceCode,
) error {
	if s.err != nil {
		return s.err
	}
	s.deviceCodes[data.DeviceCode] = data
	return nil
}

func (s *fakeTokenStore) UpdateDeviceCode(
	_ context.Context,
	data oauth.DeviceCode,
) error {
	if s.err != nil {
		return s.err
	}
	s.deviceCodes[data.DeviceCode] = data
	return nil
}

func (s *fakeTokenStore) TouchDeviceCode(
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

func (s *fakeTokenStore) DeleteDeviceCode(
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

var _ oauth.TokenStore = (*fakeTokenStore)(nil)

// discardLogger returns a logger that drops all records.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// newProposal assembles an [oauth.Proposal] for direct grant testing.
func newProposal(
	c oauth.Client,
	sessions oauth.TokenStore,
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

// newDigest fingerprints v with the default hasher, mirroring the default
// [oauth.Proposal] configuration.
func newDigest(v string) oauth.Digest {
	return oauth.Digest(digest.DefaultHasher.String(v))
}
