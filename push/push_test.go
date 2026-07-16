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

package push_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/push"
	"github.com/deep-rent/nexus/sign"
)

func generateECDSAPEM(t *testing.T) []byte {
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

func generateRSAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := sign.Encode(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem)
}

func TestMessage_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		msg  *push.Message
		err  error
	}{
		{
			name: "nil message",
			msg:  nil,
			err:  push.ErrNilMessage,
		},
		{
			name: "missing target",
			msg:  push.NewMessage("T", "B", push.Target{}),
			err:  push.ErrMissingTarget,
		},
		{
			name: "valid with token",
			msg:  push.NewMessage("T", "B", push.Target{Token: "tok123"}),
			err:  nil,
		},
		{
			name: "valid with topic",
			msg:  push.NewMessage("T", "B", push.Target{Topic: "news"}),
			err:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.msg.Validate()
			if !errors.Is(err, tt.err) {
				t.Errorf("got %v; want %v", err, tt.err)
			}
		})
	}
}

func TestAPNS_Send(t *testing.T) {
	t.Parallel()

	pemData := generateECDSAPEM(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/3/device/") {
			t.Errorf("got path %s", r.URL.Path)
		}
		if got := r.Header.Get("apns-push-type"); got != "alert" {
			t.Errorf("got push type %q", got)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "bearer ") {
			t.Errorf("missing or invalid authorization header")
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	sender := push.APNS(
		"keyID",
		"teamID",
		pemData,
		push.WithAPNSBaseURL(ts.URL),
		push.WithAPNSLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)

	msg := push.NewMessage("Hello", "World", push.Target{Token: "device123"})
	err := sender.Send(t.Context(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test missing target token
	msgTopic := push.NewMessage("Hello", "World", push.Target{Topic: "news"})
	err = sender.Send(t.Context(), msgTopic)
	if err == nil {
		t.Fatal("expected error for missing APNs token")
	}
}

func TestFCM_Send(t *testing.T) {
	t.Parallel()

	rsaPEM := generateRSAPEM(t)
	sa := map[string]string{
		"project_id":   "my-project",
		"private_key":  rsaPEM,
		"client_email": "test@my-project.iam.gserviceaccount.com",
	}
	saJSON, _ := json.Marshal(sa)

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token": "mock-token", "expires_in": 3600}`))
	})
	mux.HandleFunc("/v1/projects/my-project/messages:send", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer mock-token" {
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
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	sender := push.FCM(
		saJSON,
		push.WithFCMBaseURL(ts.URL),
		push.WithFCMOAuthURL(ts.URL+"/token"),
		push.WithFCMLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)

	msg := push.NewMessage("Title", "Body", push.Target{Topic: "news"})
	err := sender.Send(t.Context(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
