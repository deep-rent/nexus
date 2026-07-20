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

package otp_test

import (
	"context"
	"errors"
	"testing"

	"github.com/deep-rent/nexus/mail"
	"github.com/deep-rent/nexus/otp"
	"github.com/deep-rent/nexus/sms"
)

// fakeSMSSender is an in-memory [sms.Sender] that records dispatched
// messages.
type fakeSMSSender struct {
	messages []*sms.Message
	err      error
}

func (s *fakeSMSSender) Send(_ context.Context, msg *sms.Message) error {
	if s.err != nil {
		return s.err
	}
	s.messages = append(s.messages, msg)
	return nil
}

var _ sms.Sender = (*fakeSMSSender)(nil)

// fakeMailSender is an in-memory [mail.Sender] that records dispatched
// messages.
type fakeMailSender struct {
	messages []*mail.Message
	err      error
}

func (s *fakeMailSender) Send(_ context.Context, msg *mail.Message) error {
	if s.err != nil {
		return s.err
	}
	s.messages = append(s.messages, msg)
	return nil
}

var _ mail.Sender = (*fakeMailSender)(nil)

func TestGenerate(t *testing.T) {
	t.Parallel()

	lengths := []int{1, 4, 6, 8, 12}
	for _, n := range lengths {
		code, err := otp.Generate(n)
		if err != nil {
			t.Fatalf("Generate(%d) returned error: %v", n, err)
		}
		if len(code) != n {
			t.Errorf("Generate(%d) = %q; want length %d", n, code, n)
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Errorf("Generate(%d) = %q; contains non-digit %q", n, code, c)
			}
		}
	}
}

func TestGenerate_Uniform(t *testing.T) {
	t.Parallel()

	// A crude uniformity check: over many draws, every digit must occur.
	// This catches gross sampling mistakes (e.g., missing digits due to a
	// wrong rejection limit) without being flaky.
	seen := make(map[rune]int)
	for range 200 {
		code, err := otp.Generate(otp.DefaultLength)
		if err != nil {
			t.Fatalf("Generate returned error: %v", err)
		}
		for _, c := range code {
			seen[c]++
		}
	}
	for c := '0'; c <= '9'; c++ {
		if seen[c] == 0 {
			t.Errorf("digit %q never generated across 1200 samples", c)
		}
	}
}

func TestGenerate_PanicsOnInvalidLength(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Generate(%d) did not panic", n)
				}
			}()
			_, _ = otp.Generate(n)
		}()
	}
}

func TestNewSMSChannel_Panics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		sender sms.Sender
		from   string
		format string
	}{
		{
			name:   "nil sender",
			sender: nil,
			from:   "+15551234567",
		},
		{
			name:   "missing from",
			sender: &fakeSMSSender{},
			from:   "",
		},
		{
			name:   "format without verb",
			sender: &fakeSMSSender{},
			from:   "+15551234567",
			format: "no verb here",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Error("NewSMSChannel did not panic")
				}
			}()
			otp.NewSMSChannel(tt.sender, tt.from, tt.format)
		})
	}
}

func TestSMSSender_Send(t *testing.T) {
	t.Parallel()

	fake := &fakeSMSSender{}
	sender := otp.NewSMSChannel(fake, "+15551234567", "")

	if err := sender.Send(
		t.Context(),
		"+15558675309",
		"042917",
	); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	if len(fake.messages) != 1 {
		t.Fatalf("got %d messages; want 1", len(fake.messages))
	}

	msg := fake.messages[0]
	if msg.To != "+15558675309" {
		t.Errorf("got to %q; want %q", msg.To, "+15558675309")
	}
	if msg.From != "+15551234567" {
		t.Errorf("got from %q; want %q", msg.From, "+15551234567")
	}
	want := "Your verification code is 042917."
	if msg.Body != want {
		t.Errorf("got body %q; want %q", msg.Body, want)
	}
}

func TestSMSSender_Send_CustomFormat(t *testing.T) {
	t.Parallel()

	fake := &fakeSMSSender{}
	sender := otp.NewSMSChannel(fake, "+15551234567", "%s is your login code")

	if err := sender.Send(t.Context(), "+15558675309", "123456"); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	want := "123456 is your login code"
	if got := fake.messages[0].Body; got != want {
		t.Errorf("got body %q; want %q", got, want)
	}
}

func TestSMSSender_Send_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		to   string
		code string
		err  error
	}{
		{
			name: "missing to",
			to:   "",
			code: "123456",
			err:  otp.ErrMissingTo,
		},
		{
			name: "missing code",
			to:   "+15558675309",
			code: "",
			err:  otp.ErrMissingCode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sender := otp.NewSMSChannel(&fakeSMSSender{}, "+15551234567", "")
			err := sender.Send(t.Context(), tt.to, tt.code)
			if !errors.Is(err, tt.err) {
				t.Errorf("got %v; want %v", err, tt.err)
			}
		})
	}
}

func TestSMSSender_Send_PropagatesError(t *testing.T) {
	t.Parallel()

	boom := errors.New("boom")
	sender := otp.NewSMSChannel(&fakeSMSSender{err: boom}, "+15551234567", "")

	if err := sender.Send(
		t.Context(),
		"+15558675309",
		"123456",
	); !errors.Is(err, boom) {
		t.Errorf("got %v; want %v", err, boom)
	}
}

func TestNewMailChannel_Panics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		sender     mail.Sender
		from       mail.Mail
		templateID string
	}{
		{
			name:       "nil sender",
			sender:     nil,
			from:       mail.New("no-reply@example.com", ""),
			templateID: "tpl-1",
		},
		{
			name:       "missing from",
			sender:     &fakeMailSender{},
			from:       mail.Mail{},
			templateID: "tpl-1",
		},
		{
			name:       "missing template ID",
			sender:     &fakeMailSender{},
			from:       mail.New("no-reply@example.com", ""),
			templateID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Error("NewMailChannel did not panic")
				}
			}()
			otp.NewMailChannel(tt.sender, tt.from, tt.templateID, "")
		})
	}
}

func TestMailSender_Send(t *testing.T) {
	t.Parallel()

	fake := &fakeMailSender{}
	from := mail.New("no-reply@example.com", "Example")
	sender := otp.NewMailChannel(fake, from, "tpl-1", "")

	if err := sender.Send(
		t.Context(),
		"alice@example.com",
		"042917",
	); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	if len(fake.messages) != 1 {
		t.Fatalf("got %d messages; want 1", len(fake.messages))
	}

	msg := fake.messages[0]
	if msg.From != from {
		t.Errorf("got from %v; want %v", msg.From, from)
	}
	if msg.TemplateID != "tpl-1" {
		t.Errorf("got template ID %q; want %q", msg.TemplateID, "tpl-1")
	}
	if len(msg.Recipients) != 1 || len(msg.Recipients[0].To) != 1 {
		t.Fatalf("unexpected recipients: %+v", msg.Recipients)
	}
	if got := msg.Recipients[0].To[0].Addr; got != "alice@example.com" {
		t.Errorf("got recipient %q; want %q", got, "alice@example.com")
	}
	if got := msg.Recipients[0].TemplateData[otp.DefaultTemplateDataKey]; got != "042917" {
		t.Errorf("got template data %q; want %q", got, "042917")
	}
}

func TestMailSender_Send_CustomDataKey(t *testing.T) {
	t.Parallel()

	fake := &fakeMailSender{}
	sender := otp.NewMailChannel(
		fake,
		mail.New("no-reply@example.com", ""),
		"tpl-1",
		"otp",
	)

	if err := sender.Send(
		t.Context(),
		"alice@example.com",
		"123456",
	); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	if got := fake.messages[0].Recipients[0].TemplateData["otp"]; got != "123456" {
		t.Errorf("got template data %q; want %q", got, "123456")
	}
}

func TestMailSender_Send_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		to   string
		code string
		err  error
	}{
		{
			name: "missing to",
			to:   "",
			code: "123456",
			err:  otp.ErrMissingTo,
		},
		{
			name: "missing code",
			to:   "alice@example.com",
			code: "",
			err:  otp.ErrMissingCode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sender := otp.NewMailChannel(
				&fakeMailSender{},
				mail.New("no-reply@example.com", ""),
				"tpl-1",
				"",
			)
			err := sender.Send(t.Context(), tt.to, tt.code)
			if !errors.Is(err, tt.err) {
				t.Errorf("got %v; want %v", err, tt.err)
			}
		})
	}
}

func TestMailSender_Send_PropagatesError(t *testing.T) {
	t.Parallel()

	boom := errors.New("boom")
	sender := otp.NewMailChannel(
		&fakeMailSender{err: boom},
		mail.New("no-reply@example.com", ""),
		"tpl-1",
		"",
	)

	if err := sender.Send(
		t.Context(),
		"alice@example.com",
		"123456",
	); !errors.Is(err, boom) {
		t.Errorf("got %v; want %v", err, boom)
	}
}
