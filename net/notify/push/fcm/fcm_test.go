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

package fcm_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/net/notify/push"
	"github.com/deep-rent/nexus/net/notify/push/fcm"
	"github.com/deep-rent/nexus/sec/sign"
)

func generate(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := sign.Encode(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

type mockTransport struct {
	fn func(*http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return m.fn(r)
}

func TestFCM_Send(t *testing.T) {
	t.Parallel()

	key := generate(t)
	tr := &mockTransport{
		fn: func(r *http.Request) (*http.Response, error) {
			if strings.Contains(r.URL.Path, "/token") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(
						strings.NewReader(
							`{"access_token": "mock-token", "expires_in": 3600}`,
						),
					),
					Header: http.Header{
						"Content-Type": []string{"application/json"},
					},
				}, nil
			}

			if got := r.Header.Get(
				"Authorization",
			); got != "Bearer mock-token" {
				t.Errorf("invalid authorization header: %q", got)
			}

			body, _ := io.ReadAll(r.Body)
			var payload map[string]any
			_ = json.Unmarshal(body, &payload)

			msg, ok := payload["message"].(map[string]any)
			if !ok {
				t.Errorf("missing message struct in payload")
			}
			if msg["topic"] != "news" {
				t.Errorf("expected topic=news, got %v", msg["topic"])
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{}`)),
				Header:     make(http.Header),
			}, nil
		},
	}

	sender := fcm.New(
		fcm.Credentials{
			ProjectID:   "my-project",
			ClientEmail: "test@my-project.iam.gserviceaccount.com",
			PrivateKey:  string(key),
		},
		fcm.WithClient(&http.Client{Timeout: 1 * time.Second, Transport: tr}),
		fcm.WithBaseURL("https://fcm.googleapis.com/v1"),
		fcm.WithAuthURL("https://oauth2.googleapis.com/token"),
		fcm.WithLogger(log.Silent()),
	)

	msg := push.NewMessage("Title", "Body", push.Target{Topic: "news"})
	err := sender.Send(t.Context(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// A Google service account file must unmarshal directly into Credentials,
// which requires PrivateKey to be a string: a byte slice would be decoded as
// base64 and fail on the PEM contents.
func TestCredentials_UnmarshalServiceAccount(t *testing.T) {
	t.Parallel()

	pem := generate(t)

	// A service account file stores the key as a JSON string. Build one and
	// round-trip it, so the escaped newlines match the real format.
	sa := map[string]any{
		"project_id":   "my-project",
		"client_email": "svc@my-project.iam.gserviceaccount.com",
		"private_key":  string(pem),
	}
	raw, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("marshaling fixture: %v", err)
	}

	var cred fcm.Credentials
	if err := json.Unmarshal(raw, &cred); err != nil {
		t.Fatalf("a service account file must unmarshal: %v", err)
	}

	if cred.ProjectID != "my-project" {
		t.Errorf("project: got %q; want %q", cred.ProjectID, "my-project")
	}
	if cred.PrivateKey != string(pem) {
		t.Error("private key did not survive unmarshaling")
	}

	// The unmarshaled credentials must be usable, i.e. the key parses.
	if sender := fcm.New(cred); sender == nil {
		t.Error("New returned nil for unmarshaled credentials")
	}
}
