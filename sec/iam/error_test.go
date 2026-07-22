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
	"encoding/json/v2"
	"errors"
	"github.com/deep-rent/nexus/sec/iam/oauth"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// withLogger installs a logger that writes into buf, so that a test can
// inspect what the server recorded.
func withLogger(buf *bytes.Buffer, level slog.Level) Option {
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: level,
	}))
	return func(s *Server) { s.logger = logger }
}

// failingGrant reports the given error from Authorize.
type failingGrant struct{ err error }

func (g *failingGrant) Type() oauth.GrantType { return oauth.GrantTypeClientCredentials }

func (g *failingGrant) Authorize(
	context.Context,
	*oauth.Proposal,
) (*oauth.Issuance, error) {
	return nil, g.err
}

// A grant that fails unexpectedly must be logged once, by the boundary, with
// an identifier the client can quote back.
func TestServer_LogsServerErrors(t *testing.T) {
	const detail = "dial tcp 10.0.0.1:5432: connection refused"

	var buf bytes.Buffer
	env := newTestEnv(t,
		withLogger(&buf, slog.LevelDebug),
		WithGrant(&failingGrant{
			err: &oauth.Error{
				Status:      http.StatusInternalServerError,
				Code:        oauth.ErrorCodeServerError,
				Description: "the session store is unavailable",
				Cause:       errors.New(detail),
			},
		}),
	)

	res := env.postForm("/token", url.Values{
		"grant_type": {string(oauth.GrantTypeClientCredentials)},
	}, env.client, env.client.secret)

	if got := res.Code; got != http.StatusInternalServerError {
		t.Fatalf("status: got %d; want 500", got)
	}

	body := res.Body.String()
	logs := buf.String()

	// The cause is for the operator, not the client.
	if strings.Contains(body, detail) {
		t.Errorf("cause leaked to the client: %q", body)
	}

	if !strings.Contains(logs, detail) {
		t.Errorf("cause missing from the logs: %q", logs)
	}

	var oerr oauth.Error
	if err := json.Unmarshal(res.Body.Bytes(), &oerr); err != nil {
		t.Fatalf("decoding %q: %v", body, err)
	}

	if oerr.ID == "" {
		t.Fatal("response carries no error ID")
	}

	if !strings.Contains(logs, oerr.ID) {
		t.Errorf("error ID %q not found in logs %q", oerr.ID, logs)
	}

	if !strings.Contains(logs, "level=ERROR") {
		t.Errorf("server error not logged at error level: %q", logs)
	}
}

// Protocol errors are ordinary traffic and must not be reported as failures
// of the server.
func TestServer_ProtocolErrorsAreNotErrors(t *testing.T) {
	var buf bytes.Buffer
	env := newTestEnv(t, withLogger(&buf, slog.LevelDebug))

	res := env.postForm("/token", url.Values{
		"grant_type": {"no_such_grant"},
	}, env.client, env.client.secret)

	if res.Code < 400 || res.Code >= 500 {
		t.Fatalf("status: got %d; want a client error", res.Code)
	}

	logs := buf.String()

	if strings.Contains(logs, "level=ERROR") {
		t.Errorf("protocol error logged at error level: %q", logs)
	}

	if !strings.Contains(logs, "level=DEBUG") {
		t.Errorf("protocol error not logged at debug level: %q", logs)
	}
}

// A protocol error is not something a client reports back, so minting an
// identifier for every one of them would be wasted work.
func TestServer_ProtocolErrorHasNoID(t *testing.T) {
	var buf bytes.Buffer
	env := newTestEnv(t, withLogger(&buf, slog.LevelDebug))

	res := env.postForm("/token", url.Values{
		"grant_type": {"no_such_grant"},
	}, env.client, env.client.secret)

	var oerr oauth.Error
	if err := json.Unmarshal(res.Body.Bytes(), &oerr); err != nil {
		t.Fatalf("decoding %q: %v", res.Body.String(), err)
	}

	if oerr.ID != "" {
		t.Errorf("got ID %q; want none", oerr.ID)
	}
}

// Nothing is formatted when the level is disabled.
func TestServer_RespectsLogLevel(t *testing.T) {
	var buf bytes.Buffer
	env := newTestEnv(t, withLogger(&buf, slog.LevelError))

	env.postForm("/token", url.Values{
		"grant_type": {"no_such_grant"},
	}, env.client, env.client.secret)

	if buf.Len() != 0 {
		t.Errorf("got %q; want nothing logged below the level", buf.String())
	}
}

func TestError_Unwrap(t *testing.T) {
	cause := errors.New("underlying")
	err := &oauth.Error{
		Status:      http.StatusInternalServerError,
		Code:        oauth.ErrorCodeServerError,
		Description: "something broke",
		Cause:       cause,
	}

	if !errors.Is(err, cause) {
		t.Errorf("got %v; want %v", err, cause)
	}
}
