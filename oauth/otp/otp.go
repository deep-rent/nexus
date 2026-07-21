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

	"github.com/deep-rent/nexus/notify/mail"
	"github.com/deep-rent/nexus/notify/push"
	"github.com/deep-rent/nexus/notify/text"
)

const (
	// DefaultLength is the conventional code length used when consumers do
	// not specify their own. Six digits match the format users know from
	// TOTP authenticator apps and carrier-grade verification flows.
	DefaultLength = 6
	// DefaultFormat is the message body used by [ViaText] and [ViaPush] when
	// no custom format is given. It contains a single %s verb for the code.
	DefaultFormat = "Your verification code is %s."
	// DefaultTemplateDataKey is the template variable name under which
	// [ViaMail] exposes the code when no custom key is given.
	DefaultTemplateDataKey = "code"
)

var (
	// ErrMissingTo is returned by a [Deliverer] when its destination is empty.
	ErrMissingTo = errors.New("destination is needed")
	// ErrMissingCode is returned by a [Deliverer] when the code is empty.
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

// Deliverer sends an already-generated code to a preconfigured destination.
//
// It replaces the former Channel interface: because the consumer builds a
// Deliverer with full knowledge of the recipient, it can localize copy or pick
// a template per subject without the challenge engine knowing any of that. The
// [ViaText], [ViaMail], and [ViaPush] helpers construct the common cases, but
// any closure of this shape is a valid delivery mechanism.
//
// Implementations should be safe for concurrent use and honor the context.
type Deliverer func(ctx context.Context, code string) error

// Method is one enrolled way to reach a subject with a challenge, such as an
// SMS to a specific number or an email in the subject's locale.
type Method struct {
	// ID is a stable identifier the client uses to select this method — for
	// example on resend to switch channels (e.g. "sms", "email", "push"). It
	// is opaque to the engine.
	ID string
	// Label is an optional human-facing hint for pickers, such as a masked
	// address ("+1 ••• ••09"). It never carries a secret.
	Label string
	// Deliver sends the code. It is built by whoever knows the subject, so it
	// owns all destination, formatting, template, and locale choices.
	Deliver Deliverer
}

// ViaText returns a [Deliverer] that sends the code as a text message through
// the given [text.Sender].
//
// The from and to addresses follow Twilio's convention: bare E.164 numbers are
// delivered as SMS, and numbers wrapped by [text.WhatsApp] over WhatsApp. The
// format string must contain exactly one %s verb for the code; an empty format
// falls back to [DefaultFormat]. It panics if the sender is nil, from is
// empty, or the format lacks a %s verb — all static configuration errors.
func ViaText(sender text.Sender, from, to, format string) Deliverer {
	if sender == nil {
		panic("text sender is required")
	}
	if from == "" {
		panic("from address is required")
	}
	if format == "" {
		format = DefaultFormat
	}
	if !strings.Contains(format, "%s") {
		panic("format must contain a %s verb for the code")
	}
	return func(ctx context.Context, code string) error {
		if to == "" {
			return ErrMissingTo
		}
		if code == "" {
			return ErrMissingCode
		}
		return sender.Send(ctx, text.NewMessage(
			to, from, fmt.Sprintf(format, code),
		))
	}
}

// ViaMail returns a [Deliverer] that sends the code as a transactional email
// through the given [mail.Sender].
//
// Every email is rendered from the dynamic template identified by templateID,
// with the code exposed under dataKey; an empty dataKey falls back to
// [DefaultTemplateDataKey]. To localize, build a Method per locale with a
// locale-specific templateID. It panics if the sender is nil, the from address
// is empty, or the template ID is empty — all static configuration errors.
func ViaMail(
	sender mail.Sender,
	from mail.Mail,
	to, templateID, dataKey string,
) Deliverer {
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
	return func(ctx context.Context, code string) error {
		if to == "" {
			return ErrMissingTo
		}
		if code == "" {
			return ErrMissingCode
		}
		return sender.Send(ctx, mail.NewMessage(
			from,
			templateID,
			mail.NewRecipient(mail.New(to, "")).
				AddTemplateData(dataKey, code),
		))
	}
}

// ViaPush returns a [Deliverer] that sends the code as a push notification
// through the given [push.Sender].
//
// The notification carries the given title and a body rendered from format,
// which must contain exactly one %s verb for the code; an empty format falls
// back to [DefaultFormat]. It panics if the sender is nil or the format lacks a
// %s verb — both static configuration errors.
func ViaPush(
	sender push.Sender,
	target push.Target,
	title, format string,
) Deliverer {
	if sender == nil {
		panic("push sender is required")
	}
	if format == "" {
		format = DefaultFormat
	}
	if !strings.Contains(format, "%s") {
		panic("format must contain a %s verb for the code")
	}
	return func(ctx context.Context, code string) error {
		if code == "" {
			return ErrMissingCode
		}
		return sender.Send(ctx, push.NewMessage(
			title, fmt.Sprintf(format, code), target,
		))
	}
}
