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
	"testing"

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
