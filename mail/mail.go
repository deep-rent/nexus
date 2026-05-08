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
	Name    string
	Address string
}

// String returns the string representation of the address (e.g.,
// "Name <email@example.com>").
func (a Address) String() string {
	if a.Name == "" {
		return a.Address
	}
	return fmt.Sprintf("%s <%s>", a.Name, a.Address)
}

// Email represents a transactional email payload designed for dynamic templates.
type Email struct {
	From         Address
	To           []Address
	Cc           []Address
	Bcc          []Address
	ReplyTo      *Address // Optional Reply-To address
	TemplateID   string
	TemplateData map[string]any // Data to populate the dynamic template
}

// Validate checks if the email has the minimum required fields for sending.
func (e *Email) Validate() error {
	if e == nil {
		return ErrNilEmail
	}
	if len(e.To) == 0 {
		return ErrNoRecipients
	}
	if e.TemplateID == "" {
		return ErrNoTemplateID
	}
	return nil
}

// Sender is the interface that wraps the Send method.
type Sender interface {
	Send(ctx context.Context, email *Email) error
}
