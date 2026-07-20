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

package apns_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/push"
	"github.com/deep-rent/nexus/push/apns"
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

type mockTransport struct {
	fn func(*http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return m.fn(r)
}

func TestAPNS_Send(t *testing.T) {
	t.Parallel()

	key := generate(t)
	tr := &mockTransport{
		fn: func(r *http.Request) (*http.Response, error) {
			if !strings.HasPrefix(r.URL.Path, "/3/device/") {
				t.Errorf("got path %s", r.URL.Path)
			}
			if got := r.Header.Get("apns-push-type"); got != "alert" {
				t.Errorf("got push type %q", got)
			}
			if !strings.HasPrefix(r.Header.Get("Authorization"), "bearer ") {
				t.Errorf("missing or invalid authorization header")
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{}`)),
				Header:     make(http.Header),
			}, nil
		},
	}

	sender := apns.New(
		apns.Credentials{
			KeyID:      "keyID",
			TeamID:     "teamID",
			PrivateKey: key,
		},
		apns.WithClient(&http.Client{Timeout: 1 * time.Second, Transport: tr}),
		apns.WithBaseURL("https://api.sandbox.push.apple.com"),
		apns.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
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
