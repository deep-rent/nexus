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
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/net/notify/push"
)

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

func TestMessage_Options(t *testing.T) {
	t.Parallel()

	msg := push.NewMessage("Title", "Body", push.Target{Token: "tok"}).
		WithData(map[string]any{"key": "value"}).
		WithPriority(push.PriorityHigh).
		WithCollapseID("col").
		WithTTL(time.Hour).
		AsSilent()

	if msg.Data["key"] != "value" {
		t.Errorf("expected data key=value, got %v", msg.Data["key"])
	}
	if msg.Priority != push.PriorityHigh {
		t.Errorf("expected priority high, got %v", msg.Priority)
	}
	if msg.CollapseID != "col" {
		t.Errorf("expected collapseID col, got %v", msg.CollapseID)
	}
	if msg.TTL != time.Hour {
		t.Errorf("expected TTL 1h, got %v", msg.TTL)
	}
	if !msg.Silent {
		t.Errorf("expected silent true, got false")
	}
}

func TestAPIError(t *testing.T) {
	t.Parallel()

	err := &push.APIError{
		Status: 400,
		Body:   "bad request",
	}

	want := "api returned status 400: bad request"
	if got := err.Error(); got != want {
		t.Errorf("got %q; want %q", got, want)
	}

	if !errors.Is(err, push.ErrDispatchFailed) {
		t.Error("APIError should unwrap to ErrDispatchFailed")
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
	err := push.BatchSend(t.Context(), sender, msgs, 2)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
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
	err := push.BatchSend(t.Context(), sender, msgs, 0)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if exp, act := "mock error", err.Error(); !strings.Contains(act, exp) {
		t.Errorf("expected joined error to contain %q, got %q", exp, act)
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

	err := push.BatchSend(ctx, sender, msgs, 1)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context canceled, got %v", err)
	}
}

// A countingSender records how many messages it was asked to deliver and fails
// those whose title is "fail".
type countingSender struct {
	mu   sync.Mutex
	seen []string
}

func (c *countingSender) Send(_ context.Context, msg *push.Message) error {
	c.mu.Lock()
	c.seen = append(c.seen, msg.Title)
	c.mu.Unlock()
	if msg.Title == "fail" {
		return errors.New("mock error")
	}
	return nil
}

// A single failure must not abort the rest of the batch.
func TestBatchSend_BestEffort(t *testing.T) {
	t.Parallel()

	sender := &countingSender{}
	msgs := make([]*push.Message, 20)
	for i := range msgs {
		title := "ok"
		if i == 3 {
			title = "fail"
		}
		msgs[i] = push.NewMessage(title, "b", push.Target{Token: "t"})
	}

	err := push.BatchSend(t.Context(), sender, msgs, 4)
	if err == nil {
		t.Fatal("expected an error from the failing message")
	}

	// Every message must have been attempted despite the failure.
	if got := len(sender.seen); got != len(msgs) {
		t.Errorf("attempted: got %d; want %d (batch aborted early)",
			got, len(msgs))
	}
}

// A batch with no failures returns nil.
func TestBatchSend_AllSucceed(t *testing.T) {
	t.Parallel()

	sender := &countingSender{}
	msgs := []*push.Message{
		push.NewMessage("a", "b", push.Target{Token: "1"}),
		push.NewMessage("c", "d", push.Target{Token: "2"}),
	}

	if err := push.BatchSend(t.Context(), sender, msgs, 2); err != nil {
		t.Errorf("got %v; want nil", err)
	}
}

func TestBatchSend_Empty(t *testing.T) {
	t.Parallel()

	if err := push.BatchSend(
		t.Context(),
		&countingSender{},
		nil,
		4,
	); err != nil {
		t.Errorf("got %v; want nil", err)
	}
}

// Deliver maps a failure status to an *APIError and a success status to nil.
func TestDeliver(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{"success", http.StatusOK, "{}", false},
		{"created", http.StatusCreated, "", false},
		{
			"bad request",
			http.StatusBadRequest,
			`{"reason":"BadDeviceToken"}`,
			true,
		},
		{"server error", http.StatusInternalServerError, "boom", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var closed bool
			body := &trackedBody{
				Reader: strings.NewReader(tt.body),
				onClose: func() {
					closed = true
				},
			}
			client := &http.Client{Transport: roundTripFunc(
				func(*http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: tt.status,
						Body:       body,
						Header:     make(http.Header),
					}, nil
				},
			)}

			req, err := http.NewRequestWithContext(
				t.Context(), http.MethodPost, "http://example.com", nil,
			)
			if err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}

			err = push.Deliver(t.Context(), client, req, log.Silent())

			if tt.wantErr {
				var apiErr *push.APIError
				if !errors.As(err, &apiErr) {
					t.Fatalf("got %T; want *push.APIError", err)
				}
				if apiErr.Status != tt.status {
					t.Errorf(
						"status: got %d; want %d",
						apiErr.Status,
						tt.status,
					)
				}
				if apiErr.Body != tt.body {
					t.Errorf("body: got %q; want %q", apiErr.Body, tt.body)
				}
				if !errors.Is(err, push.ErrDispatchFailed) {
					t.Error("APIError should unwrap to ErrDispatchFailed")
				}
			} else if err != nil {
				t.Errorf("got %v; want nil", err)
			}

			if !closed {
				t.Error("response body was not closed")
			}
		})
	}
}

// Deliver wraps a transport-level failure rather than returning an APIError.
func TestDeliver_TransportError(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripFunc(
		func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		},
	)}

	req, _ := http.NewRequestWithContext(
		t.Context(), http.MethodPost, "http://example.com", nil,
	)

	err := push.Deliver(t.Context(), client, req, log.Silent())
	if err == nil {
		t.Fatal("expected an error")
	}

	if _, ok := errors.AsType[*push.APIError](err); ok {
		t.Error("a transport error should not be an *APIError")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// trackedBody reports when it is closed.
type trackedBody struct {
	*strings.Reader
	onClose func()
}

func (b *trackedBody) Close() error {
	b.onClose()
	return nil
}
