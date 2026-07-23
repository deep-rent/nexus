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

	"github.com/deep-rent/nexus/net/notify/mail"
	"github.com/deep-rent/nexus/net/notify/push"
	"github.com/deep-rent/nexus/net/notify/text"
	"github.com/deep-rent/nexus/sec/iam/otp"
	"github.com/deep-rent/nexus/sec/nonce"
)

// fakeTextSender is an in-memory [text.Sender] that records dispatched
// messages.
type fakeTextSender struct {
	messages []*text.Message
	err      error
}

func (s *fakeTextSender) Send(_ context.Context, msg *text.Message) error {
	if s.err != nil {
		return s.err
	}
	s.messages = append(s.messages, msg)
	return nil
}

var _ text.Sender = (*fakeTextSender)(nil)

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

// fakePushSender is an in-memory [push.Sender] that records dispatched
// messages.
type fakePushSender struct {
	messages []*push.Message
	err      error
}

func (s *fakePushSender) Send(_ context.Context, msg *push.Message) error {
	if s.err != nil {
		return s.err
	}
	s.messages = append(s.messages, msg)
	return nil
}

var _ push.Sender = (*fakePushSender)(nil)

func TestDigits(t *testing.T) {
	t.Parallel()

	// A sampler over [otp.Digits] must yield codes of the requested length
	// containing digits only; over many draws, every digit must occur. This
	// catches gross alphabet mistakes without being flaky.
	seen := make(map[rune]int)
	for range 200 {
		code, err := nonce.NewSampler(
			nil,
			otp.Digits,
			otp.DefaultLength,
		).Draw(t.Context())
		if err != nil {
			t.Fatalf("Draw returned error: %v", err)
		}
		if len(code) != otp.DefaultLength {
			t.Errorf(
				"Draw = %q; want length %d",
				code,
				otp.DefaultLength,
			)
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Errorf("Draw = %q; contains non-digit %q", code, c)
			}
			seen[c]++
		}
	}
	for c := '0'; c <= '9'; c++ {
		if seen[c] == 0 {
			t.Errorf("digit %q never generated across 1200 samples", c)
		}
	}
}

func TestViaText_Panics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		sender text.Sender
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
			sender: &fakeTextSender{},
			from:   "",
		},
		{
			name:   "format without verb",
			sender: &fakeTextSender{},
			from:   "+15551234567",
			format: "no verb here",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Error("ViaText did not panic")
				}
			}()
			otp.ViaText(tt.sender, tt.from, "+15558675309", tt.format)
		})
	}
}

func TestViaText(t *testing.T) {
	t.Parallel()

	fake := &fakeTextSender{}
	deliver := otp.ViaText(fake, "+15551234567", "+15558675309", "")

	if err := deliver(t.Context(), "042917"); err != nil {
		t.Fatalf("Deliver returned error: %v", err)
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

func TestViaText_WhatsApp(t *testing.T) {
	t.Parallel()

	fake := &fakeTextSender{}
	deliver := otp.ViaText(
		fake,
		text.WhatsApp("+15551234567"),
		text.WhatsApp("+15558675309"),
		"",
	)

	if err := deliver(t.Context(), "123456"); err != nil {
		t.Fatalf("Deliver returned error: %v", err)
	}

	msg := fake.messages[0]
	if msg.To != "whatsapp:+15558675309" {
		t.Errorf("got to %q; want a whatsapp: address", msg.To)
	}
	if msg.From != "whatsapp:+15551234567" {
		t.Errorf("got from %q; want a whatsapp: address", msg.From)
	}
}

func TestViaText_CustomFormat(t *testing.T) {
	t.Parallel()

	fake := &fakeTextSender{}
	deliver := otp.ViaText(
		fake, "+15551234567", "+15558675309", "%s is your login code",
	)

	if err := deliver(t.Context(), "123456"); err != nil {
		t.Fatalf("Deliver returned error: %v", err)
	}

	want := "123456 is your login code"
	if got := fake.messages[0].Body; got != want {
		t.Errorf("got body %q; want %q", got, want)
	}
}

func TestViaText_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		to   string
		code string
		err  error
	}{
		{name: "missing to", to: "", code: "123456", err: otp.ErrMissingTo},
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
			deliver := otp.ViaText(&fakeTextSender{}, "+15551234567", tt.to, "")
			if err := deliver(t.Context(), tt.code); !errors.Is(err, tt.err) {
				t.Errorf("got %v; want %v", err, tt.err)
			}
		})
	}
}

func TestViaText_PropagatesError(t *testing.T) {
	t.Parallel()

	boom := errors.New("boom")
	deliver := otp.ViaText(
		&fakeTextSender{err: boom}, "+15551234567", "+15558675309", "",
	)

	if err := deliver(t.Context(), "123456"); !errors.Is(err, boom) {
		t.Errorf("got %v; want %v", err, boom)
	}
}

func TestViaMail_Panics(t *testing.T) {
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
					t.Error("ViaMail did not panic")
				}
			}()
			otp.ViaMail(
				tt.sender, tt.from, "alice@example.com", tt.templateID, "",
			)
		})
	}
}

func TestViaMail(t *testing.T) {
	t.Parallel()

	fake := &fakeMailSender{}
	from := mail.New("no-reply@example.com", "Example")
	deliver := otp.ViaMail(fake, from, "alice@example.com", "tpl-1", "")

	if err := deliver(t.Context(), "042917"); err != nil {
		t.Fatalf("Deliver returned error: %v", err)
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
	got := msg.Recipients[0].TemplateData[otp.DefaultTemplateDataKey]
	if got != "042917" {
		t.Errorf("got template data %q; want %q", got, "042917")
	}
}

func TestViaMail_CustomDataKey(t *testing.T) {
	t.Parallel()

	fake := &fakeMailSender{}
	deliver := otp.ViaMail(
		fake, mail.New("no-reply@example.com", ""),
		"alice@example.com", "tpl-1", "otp",
	)

	if err := deliver(t.Context(), "123456"); err != nil {
		t.Fatalf("Deliver returned error: %v", err)
	}

	if got := fake.messages[0].Recipients[0].TemplateData["otp"]; got != "123456" {
		t.Errorf("got template data %q; want %q", got, "123456")
	}
}

func TestViaMail_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		to   string
		code string
		err  error
	}{
		{name: "missing to", to: "", code: "123456", err: otp.ErrMissingTo},
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
			deliver := otp.ViaMail(
				&fakeMailSender{}, mail.New("no-reply@example.com", ""),
				tt.to, "tpl-1", "",
			)
			if err := deliver(t.Context(), tt.code); !errors.Is(err, tt.err) {
				t.Errorf("got %v; want %v", err, tt.err)
			}
		})
	}
}

func TestViaPush(t *testing.T) {
	t.Parallel()

	fake := &fakePushSender{}
	target := push.Target{Token: "device-token"}
	deliver := otp.ViaPush(fake, target, "Sign-in", "Your code is %s")

	if err := deliver(t.Context(), "042917"); err != nil {
		t.Fatalf("Deliver returned error: %v", err)
	}

	if len(fake.messages) != 1 {
		t.Fatalf("got %d messages; want 1", len(fake.messages))
	}
	msg := fake.messages[0]
	if msg.Title != "Sign-in" {
		t.Errorf("got title %q; want %q", msg.Title, "Sign-in")
	}
	if want := "Your code is 042917"; msg.Body != want {
		t.Errorf("got body %q; want %q", msg.Body, want)
	}
	if msg.Target.Token != "device-token" {
		t.Errorf(
			"got target token %q; want %q",
			msg.Target.Token,
			"device-token",
		)
	}
}

func TestViaPush_Panics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		sender push.Sender
		format string
	}{
		{name: "nil sender", sender: nil, format: "%s"},
		{
			name:   "format without verb",
			sender: &fakePushSender{},
			format: "no verb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Error("ViaPush did not panic")
				}
			}()
			otp.ViaPush(tt.sender, push.Target{Token: "t"}, "Title", tt.format)
		})
	}
}

func TestViaPush_MissingCode(t *testing.T) {
	t.Parallel()

	deliver := otp.ViaPush(&fakePushSender{}, push.Target{Token: "t"}, "T", "")
	if err := deliver(t.Context(), ""); !errors.Is(err, otp.ErrMissingCode) {
		t.Errorf("got %v; want %v", err, otp.ErrMissingCode)
	}
}
