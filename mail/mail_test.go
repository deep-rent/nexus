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

package mail_test

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/mail"
)

type mockRoundTripper struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (m mockRoundTripper) RoundTrip(
	req *http.Request,
) (*http.Response, error) {
	return m.roundTrip(req)
}

var _ http.RoundTripper = (*mockRoundTripper)(nil)

func mockHTTPClient(
	t *testing.T,
	res *http.Response,
	err error,
) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: mockRoundTripper{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				return res, err
			},
		},
	}
}

func TestAPIError_Error(t *testing.T) {
	t.Parallel()

	err := &mail.APIError{Status: 400, Body: "bad request"}
	want := "mail: api returned status 400: bad request"

	if got := err.Error(); got != want {
		t.Errorf("Error() = %q; want %q", got, want)
	}
}

func TestAPIError_Unwrap(t *testing.T) {
	t.Parallel()

	err := &mail.APIError{Status: 500, Body: "server error"}
	if !errors.Is(err, mail.ErrDispatchFailed) {
		t.Errorf("errors.Is(err, ErrDispatchFailed) = false; want true")
	}
}

func TestMail_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give mail.Mail
		want string
	}{
		{
			name: "with name",
			give: mail.New("alice@example.com", "Alice"),
			want: "Alice <alice@example.com>",
		},
		{
			name: "without name",
			give: mail.New("bob@example.com", ""),
			want: "bob@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := tt.give.String(), tt.want; got != want {
				t.Errorf("String() = %q; want %q", got, want)
			}
		})
	}
}

func TestRecipient_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give *mail.Recipient
		want error
	}{
		{
			name: "valid recipient",
			give: mail.NewRecipient(mail.New("user@a.com", "")),
			want: nil,
		},
		{
			name: "nil recipient",
			give: nil,
			want: mail.ErrMissingRecipients,
		},
		{
			name: "empty to list",
			give: &mail.Recipient{},
			want: mail.ErrMissingRecipients,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.give.Validate()
			if got, want := err, tt.want; !errors.Is(got, want) {
				t.Errorf("Validate() = %v; want %v", got, want)
			}
		})
	}
}

func TestRecipient_Builders(t *testing.T) {
	t.Parallel()

	base := mail.New("base@a.com", "")
	r := mail.NewRecipient(base)

	r.AddTo(mail.New("a1@a.com", "")).
		AddCC(mail.New("cc1@a.com", "")).
		AddTemplateData("key", "val")

	if got, want := len(r.To), 2; got != want {
		t.Errorf("len(To) = %d; want %d", got, want)
	}
	if got, want := len(r.CC), 1; got != want {
		t.Errorf("len(CC) = %d; want %d", got, want)
	}
	if got, want := r.TemplateData["key"], "val"; got != want {
		t.Errorf("TemplateData[key] = %v; want %v", got, want)
	}

	data := map[string]any{"new": "data"}
	r.SetTemplateData(data)
	if got, want := r.TemplateData, data; !reflect.DeepEqual(got, want) {
		t.Errorf("TemplateData = %v; want %v", got, want)
	}
}

func TestMessage_Validate(t *testing.T) {
	t.Parallel()

	validMail := mail.New("from@example.com", "")
	validRecipient := mail.NewRecipient(mail.New("to@example.com", ""))

	tests := []struct {
		name string
		give *mail.Message
		want error
	}{
		{
			name: "valid message",
			give: mail.NewMessage(validMail, "t-123", validRecipient),
			want: nil,
		},
		{
			name: "nil message",
			give: nil,
			want: mail.ErrNilMessage,
		},
		{
			name: "missing from address",
			give: mail.NewMessage(mail.Mail{}, "t-123", validRecipient),
			want: mail.ErrMissingFrom,
		},
		{
			name: "missing template id",
			give: mail.NewMessage(validMail, "", validRecipient),
			want: mail.ErrMissingTemplateID,
		},
		{
			name: "no recipients",
			give: mail.NewMessage(validMail, "t-123"),
			want: mail.ErrMissingRecipients,
		},
		{
			name: "invalid recipient in list",
			give: mail.NewMessage(validMail, "t-123", &mail.Recipient{}),
			want: mail.ErrMissingRecipients,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.give.Validate()
			if got, want := err, tt.want; !errors.Is(got, want) {
				t.Errorf("Validate() = %v; want %v", got, want)
			}
		})
	}
}

func TestMessage_Builders(t *testing.T) {
	t.Parallel()

	msg := mail.NewMessage(mail.New("from@a.com", ""), "t-1")
	reply := mail.New("reply@a.com", "")

	msg.AddRecipient(mail.NewRecipient(mail.New("to@a.com", ""))).
		WithReplyTo(reply)

	if got, want := len(msg.Recipients), 1; got != want {
		t.Errorf("len(Recipients) = %d; want %d", got, want)
	}
	if msg.ReplyTo == nil {
		t.Fatalf("ReplyTo is nil")
	}
	if got, want := *msg.ReplyTo, reply; got != want {
		t.Errorf("ReplyTo = %v; want %v", got, want)
	}
}

func TestNewSender_Panics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		apiKey string
		opts   []mail.Option
	}{
		{
			name:   "empty api key",
			apiKey: "",
			opts:   nil,
		},
		{
			name:   "invalid base url",
			apiKey: "valid-key",
			opts:   []mail.Option{mail.WithBaseURL(":\x00invalid")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("NewSender() did not panic")
				}
			}()
			_ = mail.NewSender(tt.apiKey, tt.opts...)
		})
	}
}

func TestSender_Send(t *testing.T) {
	t.Parallel()

	validMessage := mail.NewMessage(
		mail.New("from@example.com", ""),
		"t-123",
		mail.NewRecipient(mail.New("to@example.com", "")),
	)

	tests := []struct {
		name    string
		msg     *mail.Message
		mockRes *http.Response
		mockErr error
		wantErr error
	}{
		{
			name: "successful dispatch",
			msg:  validMessage,
			mockRes: &http.Response{
				StatusCode: http.StatusAccepted,
				Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
			},
			wantErr: nil,
		},
		{
			name:    "validation failure",
			msg:     nil,
			wantErr: mail.ErrNilMessage,
		},
		{
			name: "provider rejection",
			msg:  validMessage,
			mockRes: &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader(`{"error":"bad"}`)),
			},
			wantErr: mail.ErrDispatchFailed,
		},
		{
			name:    "network failure",
			msg:     validMessage,
			mockErr: errors.New("connection reset by peer"),
			wantErr: errors.New("mail: request failed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := mockHTTPClient(t, tt.mockRes, tt.mockErr)
			sender := mail.NewSender(
				"test-key",
				mail.WithClient(client),
				mail.WithUserAgent("TestAgent/1.0"),
				mail.WithTimeout(1*time.Second),
			)

			err := sender.Send(t.Context(), tt.msg)

			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("Send() = %v; want nil", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("Send() = nil; want %v", tt.wantErr)
			}

			if !errors.Is(err, tt.wantErr) &&
				!strings.Contains(err.Error(), tt.wantErr.Error()) {
				t.Errorf("Send() = %v; want err containing %v", err, tt.wantErr)
			}
		})
	}
}

func TestSender_CustomLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(
		&buf,
		&slog.HandlerOptions{
			Level: slog.LevelDebug,
		},
	))

	client := mockHTTPClient(t, &http.Response{
		StatusCode: http.StatusAccepted,
		Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
	}, nil)

	sender := mail.NewSender(
		"test-key",
		mail.WithClient(client),
		mail.WithLogger(logger),
	)

	msg := mail.NewMessage(
		mail.New("from@example.com", ""),
		"t-123",
		mail.NewRecipient(mail.New("to@example.com", "")),
	)

	err := sender.Send(t.Context(), msg)
	if err != nil {
		t.Fatalf("Send() unexpected error: %v", err)
	}

	if s := buf.String(); !strings.Contains(s,
		"Dispatching message to provider") {
		t.Errorf("Expected debug log output in buffer, got: %q", s)
	}
}
