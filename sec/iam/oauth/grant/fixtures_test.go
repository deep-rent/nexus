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
	"net/url"
	"slices"
	"testing"
	"time"

	"uuid"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/iam/artifact"
	"github.com/deep-rent/nexus/sec/iam/oauth"
	"github.com/deep-rent/nexus/sys/log"
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

// fakeTokens bundles Map-backed [oauth.TokenStores] with typed handles for
// seeding and peeking.
type fakeTokens struct {
	oauth.TokenStores
	authCodes     *artifact.Map[oauth.Digest, oauth.AuthCode]
	refreshTokens *artifact.Map[oauth.Digest, oauth.RefreshToken]
	deviceCodes   *fakeDeviceCodeStore
}

func newFakeTokens() *fakeTokens {
	t := &fakeTokens{
		authCodes: artifact.NewMap(
			func(c oauth.AuthCode) oauth.Digest { return c.Code },
		),
		refreshTokens: artifact.NewMap(
			func(r oauth.RefreshToken) oauth.Digest { return r.Token },
		),
		deviceCodes: &fakeDeviceCodeStore{Map: artifact.NewMap(
			func(c oauth.DeviceCode) oauth.Digest { return c.DeviceCode },
		)},
	}
	t.TokenStores = oauth.TokenStores{
		AuthCodes:     t.authCodes,
		RefreshTokens: t.refreshTokens,
		DeviceCodes:   t.deviceCodes,
	}
	return t
}

// seed inserts a record into the store, failing the test on error.
func seed[K ~string, V any](t *testing.T, s artifact.Store[K, V], v V) {
	t.Helper()
	if err := s.Create(t.Context(), v); err != nil {
		t.Fatalf("failed to seed store: %v", err)
	}
}

// discardLogger returns a logger that drops all records.
func discardLogger() *log.Logger {
	return log.Discard()
}

// newProposal assembles an [oauth.Proposal] for direct grant testing.
func newProposal(
	c oauth.Client,
	tokens *fakeTokens,
	data url.Values,
	now time.Time,
) *oauth.Proposal {
	return oauth.NewProposal(
		c,
		tokens.TokenStores,
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
