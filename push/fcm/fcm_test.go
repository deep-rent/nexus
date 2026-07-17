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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/deep-rent/nexus/push"
	"github.com/deep-rent/nexus/push/fcm"
	"github.com/deep-rent/nexus/sign"
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

func TestFCM_Send(t *testing.T) {
	t.Parallel()

	pemData := generate(t)
	sa := map[string]string{
		"project_id":   "my-project",
		"private_key":  string(pemData),
		"client_email": "test@my-project.iam.gserviceaccount.com",
	}
	saJSON, _ := json.Marshal(sa)

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(
			[]byte(`{"access_token": "mock-token", "expires_in": 3600}`),
		)
	})
	mux.HandleFunc(
		"/v1/projects/my-project/messages:send",
		func(w http.ResponseWriter, r *http.Request) {
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

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		},
	)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	sender := fcm.New(
		&http.Client{Timeout: 1 * time.Second},
		saJSON,
		fcm.WithBaseURL(ts.URL+"/v1"),
		fcm.WithOAuthURL(ts.URL+"/token"),
		fcm.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)

	msg := push.NewMessage("Title", "Body", push.Target{Topic: "news"})
	err := sender.Send(t.Context(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
