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
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/sec/iam/oauth"
	"github.com/deep-rent/nexus/sys/log"
)

// withLogger installs a logger that captures JSON records into the returned
// buffer, so that a test can inspect what the server recorded.
func withLogger(level log.Level) (Option, *log.Buffer) {
	logger, buf := log.Capture(log.WithLevel(level))
	return func(s *Server) { s.logger = logger }, buf
}

// records unmarshals every captured JSON line into a generic map.
func records(t *testing.T, buf *log.Buffer) []map[string]any {
	t.Helper()
	lines := buf.Lines()
	recs := make([]map[string]any, len(lines))
	for i, line := range lines {
		if err := json.Unmarshal([]byte(line), &recs[i]); err != nil {
			t.Fatalf("decoding record %q: %v", line, err)
		}
	}
	return recs
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
	t.Parallel()

	const detail = "dial tcp 10.0.0.1:5432: connection refused"

	logOpt, buf := withLogger(log.LevelDebug)
	env := newTestEnv(t,
		logOpt,
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

	// The cause is for the operator, not the client.
	if strings.Contains(body, detail) {
		t.Errorf("cause leaked to the client: %q", body)
	}

	var oerr oauth.Error
	if err := json.Unmarshal(res.Body.Bytes(), &oerr); err != nil {
		t.Fatalf("decoding %q: %v", body, err)
	}

	if oerr.ID == "" {
		t.Fatal("response carries no error ID")
	}

	var rec map[string]any
	for _, r := range records(t, buf) {
		if r["level"] == "error" {
			rec = r
			break
		}
	}
	if rec == nil {
		t.Fatalf("server error not logged at error level: %q", buf.String())
	}

	if got, _ := rec["error"].(string); !strings.Contains(got, detail) {
		t.Errorf("cause missing from the logs: %q", buf.String())
	}

	if got, _ := rec["error_id"].(string); got != oerr.ID {
		t.Errorf("error_id: got %q; want %q", got, oerr.ID)
	}
}

// Protocol errors are ordinary traffic and must not be reported as failures
// of the server.
func TestServer_ProtocolErrorsAreNotErrors(t *testing.T) {
	t.Parallel()

	logOpt, buf := withLogger(log.LevelDebug)
	env := newTestEnv(t, logOpt)

	res := env.postForm("/token", url.Values{
		"grant_type": {"no_such_grant"},
	}, env.client, env.client.secret)

	if res.Code < 400 || res.Code >= 500 {
		t.Fatalf("status: got %d; want a client error", res.Code)
	}

	debug := false
	for _, r := range records(t, buf) {
		switch r["level"] {
		case "error":
			t.Errorf("protocol error logged at error level: %q", buf.String())
		case "debug":
			debug = true
		}
	}

	if !debug {
		t.Errorf("protocol error not logged at debug level: %q", buf.String())
	}
}

// A protocol error is not something a client reports back, so minting an
// identifier for every one of them would be wasted work.
func TestServer_ProtocolErrorHasNoID(t *testing.T) {
	t.Parallel()

	logOpt, _ := withLogger(log.LevelDebug)
	env := newTestEnv(t, logOpt)

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
	t.Parallel()

	logOpt, buf := withLogger(log.LevelError)
	env := newTestEnv(t, logOpt)

	env.postForm("/token", url.Values{
		"grant_type": {"no_such_grant"},
	}, env.client, env.client.secret)

	if out := buf.String(); out != "" {
		t.Errorf("got %q; want nothing logged below the level", out)
	}
}

func TestError_Unwrap(t *testing.T) {
	t.Parallel()

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
