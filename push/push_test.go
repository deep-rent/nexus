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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	pemData := generate(t)

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

type mockSender struct {
	err error
}

func (m *mockSender) Send(ctx context.Context, msg *push.Message) error {
	if msg.Title == "fail" {
		return errors.New("mock error")
	}
	return m.err
}

func TestBatchSend_Success(t *testing.T) {
	t.Parallel()
	sender := &mockSender{}
	msgs := []*push.Message{
		push.NewMessage("1", "1", push.Target{Token: "1"}),
		push.NewMessage("2", "2", push.Target{Token: "2"}),
		push.NewMessage("3", "3", push.Target{Token: "3"}),
	}
	errs := push.BatchSend(t.Context(), sender, msgs, 2)
	if len(errs) != 3 {
		t.Fatalf("expected 3 errors, got %d", len(errs))
	}
	for i, err := range errs {
		if err != nil {
			t.Errorf("expected nil error at index %d, got %v", i, err)
		}
	}
}

func TestBatchSend_Errors(t *testing.T) {
	t.Parallel()
	sender := &mockSender{}
	msgs := []*push.Message{
		push.NewMessage("1", "1", push.Target{Token: "1"}),
		push.NewMessage("fail", "2", push.Target{Token: "2"}),
		push.NewMessage("3", "3", push.Target{Token: "3"}),
	}
	errs := push.BatchSend(t.Context(), sender, msgs, 0)
	if len(errs) != 3 {
		t.Fatalf("expected 3 errors, got %d", len(errs))
	}
	if errs[0] != nil {
		t.Errorf("expected nil at index 0")
	}
	if errs[1] == nil || errs[1].Error() != "mock error" {
		t.Errorf("expected mock error at index 1, got %v", errs[1])
	}
	if errs[2] != nil {
		t.Errorf("expected nil at index 2")
	}
}

func TestBatchSend_Cancellation(t *testing.T) {
	t.Parallel()

	sender := &mockSender{}
	msgs := []*push.Message{
		push.NewMessage("1", "1", push.Target{Token: "1"}),
		push.NewMessage("2", "2", push.Target{Token: "2"}),
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately

	errs := push.BatchSend(ctx, sender, msgs, 1)
	if len(errs) != 2 {
		t.Fatalf("expected 2 errors, got %d", len(errs))
	}
	if !errors.Is(errs[0], context.Canceled) {
		t.Errorf("expected context canceled at index 0, got %v", errs[0])
	}
	if !errors.Is(errs[1], context.Canceled) {
		t.Errorf("expected context canceled at index 1, got %v", errs[1])
	}
}
