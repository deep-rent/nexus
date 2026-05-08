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

// Package mail provides abstractions for sending transactional emails.
//
// It defines a generic payload model ([Email]) and a common [Sender]
// interface that can be implemented by various email service providers
// (e.g., SendGrid, Mailgun, SMTP). This decouples the application's
// business logic from the specific delivery mechanism.
//
// # Usage
//
// Typically, you construct an Email using the fluent API and pass it
// to a Sender:
//
//	msg := mail.NewEmail(
//		mail.NewAddress("no-reply@example.com", "My App"),
//		"template-id-123",
//		mail.NewRecipient(mail.NewAddress("user@example.com", "Alice")).
//			WithData("name", "Alice"),
//	)
//
//	err := sender.Send(ctx, msg)
package mail

import (
	"context"
	"errors"
	"fmt"
)

var (
	// ErrNilEmail is returned when a nil email is passed to Send.
	ErrNilEmail = errors.New("mail: email cannot be nil")
	// ErrNoRecipients is returned when an email has no recipients.
	ErrNoRecipients = errors.New("mail: at least one recipient is required")
	// ErrNoTemplateID is returned when an email has no template ID.
	ErrNoTemplateID = errors.New("mail: template ID is required")
)

// Address represents an email address and an optional display name.
type Address struct {
	// Name is an optional display name (e.g., "Alice Smith").
	Name string
	// Address is the actual email address (e.g., "alice@example.com").
	Address string
}

// NewAddress creates a new Address with an optional display name.
func NewAddress(addr, name string) Address {
	return Address{Address: addr, Name: name}
}

// String returns the string representation of the address (e.g.,
// "Name <email@example.com>").
func (a Address) String() string {
	if a.Name == "" {
		return a.Address
	}
	return fmt.Sprintf("%s <%s>", a.Name, a.Address)
}

// Recipient represents a single intended recipient or group of receivers,
// along with the specific template data to be used for them.
type Recipient struct {
	// To contains the primary recipients.
	To []Address
	// CC contains the carbon copy recipients.
	CC []Address
	// BCC contains the blind carbon copy recipients.
	BCC []Address
	// TemplateData holds the key-value pairs used to populate the template
	// variables for this specific recipient group.
	TemplateData map[string]any
}

// NewRecipient creates a new Recipient group with the required primary
// destinations.
func NewRecipient(to ...Address) *Recipient {
	return &Recipient{
		To: to,
	}
}

// AddTo appends one or more recipients to the "To" list.
func (r *Recipient) AddTo(addrs ...Address) *Recipient {
	r.To = append(r.To, addrs...)
	return r
}

// AddCC appends one or more recipients to the "CC" list.
func (r *Recipient) AddCC(addrs ...Address) *Recipient {
	r.CC = append(r.CC, addrs...)
	return r
}

// AddBCC appends one or more recipients to the "BCC" list.
func (r *Recipient) AddBCC(addrs ...Address) *Recipient {
	r.BCC = append(r.BCC, addrs...)
	return r
}

// WithData adds or updates a key-value pair in the template data map.
func (r *Recipient) WithData(key string, value any) *Recipient {
	if r.TemplateData == nil {
		r.TemplateData = make(map[string]any)
	}
	r.TemplateData[key] = value
	return r
}

// SetData replaces the entire template data map.
func (r *Recipient) SetData(data map[string]any) *Recipient {
	r.TemplateData = data
	return r
}

// Validate checks if the recipient group has at least one primary destination.
func (r *Recipient) Validate() error {
	if r == nil || len(r.To) == 0 {
		return ErrNoRecipients
	}
	return nil
}

// Email represents a transactional email payload designed for dynamic
// templates.
type Email struct {
	// From is the sender's address.
	From Address
	// Recipients contains groups of receivers and their specific template data.
	Recipients []*Recipient
	// ReplyTo is an optional address where replies should be directed.
	ReplyTo *Address
	// TemplateID is the provider-specific identifier of the dynamic template to
	// use.
	TemplateID string
}

// NewEmail creates a new Email with the required fields.
func NewEmail(
	from Address,
	templateID string,
	recipients ...*Recipient,
) *Email {
	return &Email{
		From:             from,
		TemplateID:       templateID,
		Recipients:       recipients,
	}
}

// AddRecipient appends a Recipient group to the email.
func (e *Email) AddRecipient(r *Recipient) *Email {
	e.Recipients = append(e.Recipients, r)
	return e
}

// WithReplyTo sets an optional Reply-To address.
func (e *Email) WithReplyTo(addr Address) *Email {
	e.ReplyTo = &addr
	return e
}

// Validate checks if the email has the minimum required fields for sending.
func (e *Email) Validate() error {
	if e == nil {
		return ErrNilEmail
	}
	if len(e.Recipients) == 0 {
		return ErrNoRecipients
	}
	for _, r := range e.Recipients {
		if err := r.Validate(); err != nil {
			return err
		}
	}
	if e.TemplateID == "" {
		return ErrNoTemplateID
	}
	return nil
}

// Sender is the interface that wraps the Send method.
//
// Implementations of this interface are expected to be safe for concurrent
// use by multiple goroutines. They should respect the provided context for
// timeouts and cancellation.
type Sender interface {
	// Send dispatches the provided email payload to the underlying provider.
	// It returns an error if the email is invalid, if the network request
	// fails, or if the provider rejects the payload.
	Send(ctx context.Context, email *Email) error
}
