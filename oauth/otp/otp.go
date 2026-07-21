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

package otp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/deep-rent/nexus/mail"
	"github.com/deep-rent/nexus/sms"
)

const (
	// DefaultLength is the conventional code length used when consumers do
	// not specify their own. Six digits match the format users know from
	// TOTP authenticator apps and carrier-grade verification flows.
	DefaultLength = 6
	// DefaultSMSFormat is the message body used by [SMS] when no
	// custom format is given. It contains a single %s verb that receives
	// the code.
	DefaultSMSFormat = "Your verification code is %s."
	// DefaultTemplateDataKey is the template variable name under which
	// [Mail] exposes the code when no custom key is given.
	DefaultTemplateDataKey = "code"
)

var (
	// ErrMissingTo is returned when a code is sent without a destination.
	ErrMissingTo = errors.New("destination is needed")
	// ErrMissingCode is returned when an empty code is sent.
	ErrMissingCode = errors.New("code is needed")
)

// Generate returns a uniformly random numeric code of the given length,
// zero-padded (e.g., "042917"). It panics if length is not positive, since
// the length is a static configuration choice rather than runtime input.
// An error is returned only if the system randomness source fails.
func Generate(length int) (string, error) {
	if length <= 0 {
		panic("code length must be positive")
	}

	// Rejection sampling keeps the digit distribution uniform: only bytes
	// below the largest multiple of 10 are used.
	const limit = byte(250)

	digits := make([]byte, length)
	buf := make([]byte, 2*length)
	i := 0
	for i < length {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b < limit {
				digits[i] = '0' + b%10
				if i++; i == length {
					break
				}
			}
		}
	}
	return string(digits), nil
}

// Channel delivers one-time passwords to recipients over a side channel.
// The name deliberately differs from the Sender interfaces of the sms and
// mail packages: a Channel wraps such a sender and speaks in codes rather
// than messages.
//
// Implementations are expected to be safe for concurrent use by multiple
// goroutines and to respect the provided context for timeouts and
// cancellation. The meaning of the destination string depends on the
// channel: a phone number in E.164 format for SMS, an email address for
// mail.
type Channel interface {
	// Send delivers the code to the given destination. It returns an error
	// if the input is invalid, if the network request fails, or if the
	// underlying provider rejects the payload.
	Send(ctx context.Context, to, code string) error
}

// smsChannel adapts an [sms.Sender] to the [Channel] interface.
type smsChannel struct {
	sender sms.Sender
	from   string
	format string
}

var _ Channel = (*smsChannel)(nil)

// SMS returns a [Channel] that delivers codes as text messages
// through the given [sms.Sender].
//
// The from number is used as the sender of every message. The format string
// must contain exactly one %s verb, which receives the code; an empty format
// falls back to [DefaultSMSFormat]. SMS panics if the sender is
// nil, the from number is empty, or the format lacks a %s verb, since all
// three are startup configuration errors.
func SMS(sender sms.Sender, from, format string) Channel {
	if sender == nil {
		panic("sms sender is required")
	}
	if from == "" {
		panic("from number is required")
	}
	if format == "" {
		format = DefaultSMSFormat
	}
	if !strings.Contains(format, "%s") {
		panic("format must contain a %s verb for the code")
	}
	return &smsChannel{
		sender: sender,
		from:   from,
		format: format,
	}
}

// Send implements the [Channel] interface.
func (s *smsChannel) Send(ctx context.Context, to, code string) error {
	if to == "" {
		return ErrMissingTo
	}
	if code == "" {
		return ErrMissingCode
	}
	return s.sender.Send(ctx, sms.NewMessage(
		to,
		s.from,
		fmt.Sprintf(s.format, code),
	))
}

// mailChannel adapts a [mail.Sender] to the [Channel] interface.
type mailChannel struct {
	sender     mail.Sender
	from       mail.Mail
	templateID string
	dataKey    string
}

var _ Channel = (*mailChannel)(nil)

// Mail returns a [Channel] that delivers codes as transactional
// emails through the given [mail.Sender].
//
// Every email is rendered from the dynamic template identified by
// templateID, with the code exposed to the template under dataKey. An empty
// dataKey falls back to [DefaultTemplateDataKey]. Mail panics if
// the sender is nil, the from address is empty, or the template ID is
// empty, since all three are startup configuration errors.
func Mail(
	sender mail.Sender,
	from mail.Mail,
	templateID, dataKey string,
) Channel {
	if sender == nil {
		panic("mail sender is required")
	}
	if from.Addr == "" {
		panic("from address is required")
	}
	if templateID == "" {
		panic("template ID is required")
	}
	if dataKey == "" {
		dataKey = DefaultTemplateDataKey
	}
	return &mailChannel{
		sender:     sender,
		from:       from,
		templateID: templateID,
		dataKey:    dataKey,
	}
}

// Send implements the [Channel] interface.
func (s *mailChannel) Send(ctx context.Context, to, code string) error {
	if to == "" {
		return ErrMissingTo
	}
	if code == "" {
		return ErrMissingCode
	}
	return s.sender.Send(ctx, mail.NewMessage(
		s.from,
		s.templateID,
		mail.NewRecipient(mail.New(to, "")).
			AddTemplateData(s.dataKey, code),
	))
}
