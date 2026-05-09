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
//			AddData("name", "Alice"),
//	)
//
//	err := sender.Send(ctx, msg)
package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/deep-rent/nexus/retry"
)

// DefaultBaseURL is the standard API endpoint for SendGrid v3.
const DefaultBaseURL = "https://api.sendgrid.com/v3"

var (
	// ErrNilEmail is returned when a nil email is passed to Send.
	ErrNilEmail = errors.New("mail: email cannot be nil")
	// ErrNoRecipients is returned when an email has no recipients.
	ErrNoRecipients = errors.New("mail: at least one recipient is required")
	// ErrNoTemplateID is returned when an email has no template ID.
	ErrNoTemplateID = errors.New("mail: template ID is required")
)

// APIError represents an error response from the SendGrid API.
//
// It allows consumers to programmatically inspect the HTTP status code
// (e.g., to detect 429 Too Many Requests or 400 Bad Request) and parse
// the raw JSON body returned by SendGrid for specific validation errors.
type APIError struct {
	// StatusCode is the HTTP status code returned by the SendGrid API.
	StatusCode int
	// Body is the response body returned by the SendGrid API.
	Body string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("sendgrid: API error %d: %s", e.StatusCode, e.Body)
}

var _ error = (*APIError)(nil)

// Address represents an email address and an optional display name.
type Address struct {
	// Email is the actual email address (e.g., "alice@example.com").
	Email string `json:"email"`
	// Name is an optional display name (e.g., "Alice Smith").
	Name string `json:"name,omitzero"`
}

// NewAddress creates a new Address with an optional display name.
func NewAddress(addr, name string) Address {
	return Address{
		Email: addr,
		Name:  name,
	}
}

// String returns the string representation of the address (e.g.,
// "Name <email@example.com>").
func (a Address) String() string {
	if a.Name == "" {
		return a.Email
	}
	return fmt.Sprintf("%s <%s>", a.Name, a.Email)
}

// Recipient represents a single intended recipient or group of receivers,
// along with the specific template data to be used for them.
type Recipient struct {
	// To contains the primary recipients.
	To []Address `json:"to"`
	// CC contains the carbon copy recipients.
	CC []Address `json:"cc,omitzero"`
	// TemplateData holds the key-value pairs used to populate the template
	// variables for this specific recipient group.
	TemplateData map[string]any `json:"dynamic_template_data,omitzero"`
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

// AddData adds or updates a key-value pair in the template data map.
func (r *Recipient) AddData(key string, value any) *Recipient {
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
	From Address `json:"from"`
	// Recipients contains groups of receivers and their specific template data.
	Recipients []*Recipient `json:"personalizations"`
	// ReplyTo is an optional address where replies should be directed.
	ReplyTo *Address `json:"reply_to,omitzero"`
	// TemplateID is the provider-specific identifier of the dynamic template to
	// use.
	TemplateID string `json:"template_id"`
}

// NewEmail creates a new Email with the required fields.
func NewEmail(
	from Address,
	templateID string,
	recipients ...*Recipient,
) *Email {
	return &Email{
		From:       from,
		TemplateID: templateID,
		Recipients: recipients,
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

// sender is a SendGrid email sender that implements [Sender].
//
// It manages the HTTP client and authentication state required to interact
// with the SendGrid API. Once initialized via [New], a sender is safe for
// concurrent use by multiple goroutines.
type sender struct {
	apiKey  string
	baseURL string
	timeout time.Duration
	client  *http.Client
	logger  *slog.Logger
	retry   []retry.Option
}

// Option defines the functional option pattern for configuring the Client.
type Option func(*sender)

// WithClient allows passing a custom HTTP client.
// If provided, it overrides the WithTimeout setting.
func WithClient(client *http.Client) Option {
	return func(s *sender) {
		if client != nil {
			s.client = client
		}
	}
}

// WithBaseURL allows overriding the SendGrid API base URL for testing or
// mocking.
func WithBaseURL(url string) Option {
	return func(s *sender) {
		s.baseURL = url
	}
}

// WithTimeout configures the timeout for the default HTTP client.
func WithTimeout(d time.Duration) Option {
	return func(s *sender) {
		s.timeout = d
	}
}

// WithRetryOptions configures the retry mechanism for the default HTTP client.
// If a custom HTTP client is provided via WithHTTPClient, these options are
// ignored.
func WithRetryOptions(opts ...retry.Option) Option {
	return func(s *sender) {
		s.retry = append(s.retry, opts...)
	}
}

// WithLogger injects a structured logger into the client.
func WithLogger(logger *slog.Logger) Option {
	return func(s *sender) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// New creates a configured SendGrid client.
//
// It initializes the client with a default base URL, a sensible timeout,
// and a standard logger. These defaults can be overridden by passing one or
// more [Option] functions. If no custom HTTP client is provided, it builds
// an internal client optimized for API calls with connection pooling and
// automatic retry capabilities.
func New(apiKey string, opts ...Option) Sender {
	if apiKey == "" {
		panic(errors.New("sendgrid: API key is required"))
	}

	c := &sender{
		apiKey:  apiKey,
		baseURL: DefaultBaseURL,
		timeout: 10 * time.Second, // Sensible default timeout
		logger:  slog.Default(),   // Fallback to standard structured logger
	}

	for _, opt := range opts {
		opt(c)
	}

	// Initialize the default HTTP client if a custom one wasn't provided
	if c.client == nil {
		d := &net.Dialer{
			Timeout: c.timeout / 3,
		}
		var t http.RoundTripper = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           d.DialContext,
			TLSHandshakeTimeout:   c.timeout / 3,
			ResponseHeaderTimeout: c.timeout * 9 / 10,
			DisableKeepAlives:     true,
		}
		t = retry.NewTransport(t, c.retry...)
		c.client = &http.Client{
			Timeout:   c.timeout,
			Transport: t,
		}
	}

	return c
}

type personalization struct {
	To           []Address      `json:"to"`
	CC           []Address      `json:"cc,omitzero"`
	TemplateData map[string]any `json:"dynamic_template_data,omitzero"`
}

type payload struct {
	Personalizations []personalization `json:"personalizations"`
	From             Address           `json:"from"`
	ReplyTo          *Address          `json:"reply_to,omitzero"`
	TemplateID       string            `json:"template_id"`
}

// Send executes the HTTP request to the SendGrid API.
//
// It maps the domain [Email] payload into SendGrid's expected JSON
// structure and dispatches the request. It respects the provided context
// for timeouts and cancellation. If the API responds with an HTTP status
// code >= 400, it returns an [*APIError] containing the raw response body.
func (s *sender) Send(ctx context.Context, email *Email) error {
	if err := email.Validate(); err != nil {
		return err
	}

	body, err := json.Marshal(email)
	if err != nil {
		return fmt.Errorf("sendgrid: failed to marshal payload: %w", err)
	}

	url := s.baseURL + "/mail/send"
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		url,
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("sendgrid: failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	s.logger.DebugContext(ctx, "Sending email via SendGrid",
		slog.String("template_id", email.TemplateID),
		slog.String("url", url),
	)

	res, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("sendgrid: request failed: %w", err)
	}
	defer func() {
		err := res.Body.Close()
		if err != nil {
			s.logger.WarnContext(
				ctx,
				"Failed to close response body",
				slog.Any("error", err),
			)
		}
	}()

	if res.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		err := &APIError{StatusCode: res.StatusCode, Body: string(body)}
		return err
	}

	s.logger.DebugContext(ctx, "Email successfully dispatched to SendGrid",
		slog.Int("status_code", res.StatusCode),
	)

	return nil
}
