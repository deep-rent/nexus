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

package sms_test

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/nexus/sms"
)

func TestAPIError(t *testing.T) {
	t.Parallel()

	err := &sms.APIError{
		Status:  400,
		Code:    21211,
		Message: "Invalid 'To' Phone Number",
	}

	want := "api returned status 400 (code 21211): Invalid 'To' Phone Number"
	if got := err.Error(); got != want {
		t.Errorf("got %q; want %q", got, want)
	}

	if !errors.Is(err, sms.ErrDispatchFailed) {
		t.Error("APIError should unwrap to ErrDispatchFailed")
	}
}

func TestMessage_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		msg  *sms.Message
		err  error
	}{
		{
			name: "nil message",
			msg:  nil,
			err:  sms.ErrNilMessage,
		},
		{
			name: "missing to",
			msg:  sms.NewMessage("", "+1234567890", "Hello"),
			err:  sms.ErrMissingTo,
		},
		{
			name: "missing from",
			msg:  sms.NewMessage("+0987654321", "", "Hello"),
			err:  sms.ErrMissingFrom,
		},
		{
			name: "missing body",
			msg:  sms.NewMessage("+0987654321", "+1234567890", ""),
			err:  sms.ErrMissingBody,
		},
		{
			name: "valid message",
			msg:  sms.NewMessage("+0987654321", "+1234567890", "Hello"),
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

func TestNewSender_Panics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		accountSID string
		authToken  string
	}{
		{"missing accountSID", "", "token"},
		{"missing authToken", "sid", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r == nil {
					t.Error("expected a panic")
				}
			}()
			sms.NewSender(&http.Client{
				Timeout: 1 * time.Second,
			}, tt.accountSID, tt.authToken)
		})
	}
}

type mockTransport struct {
	fn func(*http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return m.fn(r)
}

func TestSender_Send(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		status     int
		body       string
		msg        *sms.Message
		wantErr    bool
		errMatches string
	}{
		{
			name:    "success",
			status:  http.StatusCreated,
			body:    `{"sid": "SM123"}`,
			msg:     sms.NewMessage("+123", "+456", "Hello"),
			wantErr: false,
		},
		{
			name:       "api error",
			status:     http.StatusBadRequest,
			body:       `{"message": "Invalid to number"}`,
			msg:        sms.NewMessage("+123", "+456", "Hello"),
			wantErr:    true,
			errMatches: "api returned status 400",
		},
		{
			name:       "invalid message",
			status:     http.StatusOK,
			msg:        sms.NewMessage("", "+456", "Hello"),
			wantErr:    true,
			errMatches: "to number is needed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tr := &mockTransport{
				fn: func(r *http.Request) (*http.Response, error) {
					if r.Method != http.MethodPost {
						t.Errorf("got method %s; want POST", r.Method)
					}

					u, p, ok := r.BasicAuth()
					if !ok || u != "sid" || p != "token" {
						t.Errorf("invalid basic auth")
					}

					if got := r.Header.Get(
						"Content-Type",
					); got != "application/x-www-form-urlencoded" {
						t.Errorf("got Content-Type %q", got)
					}

					body, _ := io.ReadAll(r.Body)
					if !strings.Contains(string(body), "To=%2B123") &&
						tt.status != http.StatusOK {
						//
					}

					return &http.Response{
						StatusCode: tt.status,
						Body:       io.NopCloser(strings.NewReader(tt.body)),
						Header:     make(http.Header),
					}, nil
				},
			}

			sender := sms.NewSender(&http.Client{
				Timeout:   1 * time.Second,
				Transport: tr,
			}, "sid", "token",
				sms.WithBaseURL("http://example.com"),
				sms.WithLogger(log.Silent()),
			)

			err := sender.Send(t.Context(), tt.msg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				if !strings.Contains(err.Error(), tt.errMatches) {
					t.Errorf(
						"error %q does not match %q", err.Error(),
						tt.errMatches,
					)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestSender_WithClientAndOptions(t *testing.T) {
	t.Parallel()

	client := &http.Client{Timeout: 1 * time.Second}
	sender := sms.NewSender(client, "sid", "token")

	if sender == nil {
		t.Fatal("sender should not be nil")
	}
}
