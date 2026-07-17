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
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/push"
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
