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
// It defines a generic payload model ([Message]) and a common [Sender]
// interface for email delivery. This decouples the application's
// business logic from the underlying mechanism. By default, this package
// provides a production-ready SendGrid implementation initialized via
// [NewSender].
//
// # Usage
//
// Typically, you initialize a [Sender] at application startup, construct
// a [Message] using the fluent API, and pass it to the sender.
//
// Example:
//
//	// 1. Initialize the default SendGrid sender.
//	sender := mail.NewSender("your-api-key")
//
//	// 2. Construct the email message.
//	msg := mail.NewMessage(
//	  mail.NewAddress("no-reply@example.com", "My App"),
//	  "template-id-123",
//	  mail.NewRecipient(mail.NewAddress("user@example.com", "Alice")).
//	    AddTemplateData("name", "Alice"),
//	)
//
//	// 3. Dispatch the email.
//	err = sender.Send(context.Background(), msg)
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
	"net/url"
	"time"

	"github.com/deep-rent/nexus/retry"
)

// DefaultBaseURL is the standard API endpoint for SendGrid v3.
const DefaultBaseURL = "https://api.sendgrid.com/v3"

var (
	// ErrNilMessage is returned when a nil [Message] is validated.
	ErrNilMessage = errors.New("mail: message cannot be nil")
	// ErrMissingRecipients is returned when an email has no recipients.
	ErrMissingRecipients = errors.New("mail: at least one recipient is required")
	// ErrMissingTemplateID is returned when an email has no template ID.
	ErrMissingTemplateID = errors.New("mail: template ID is required")
	// ErrMissingFrom is returned when an email has no sender address.
	ErrMissingFrom = errors.New("mail: from address is required")
	// ErrDispatchFailed is returned when the underlying provider rejects the
	// payload.
	ErrDispatchFailed = errors.New("mail: dispatching failed")
)

// APIError represents an error returned by the underlying email provider.
type APIError struct {
	// Status is the HTTP status code returned by the provider.
	Status int
	// Body is the raw response body returned by the provider.
	Body string
}

// Error implements [error].
func (e *APIError) Error() string {
	return fmt.Sprintf("mail: api returned status %d: %s", e.Status, e.Body)
}

// Unwrap allows [errors.Is] to match against [ErrDispatchFailed].
func (e *APIError) Unwrap() error {
	return ErrDispatchFailed
}

// Email represents an email address and an optional display name.
type Email struct {
	// Addr is the actual email address (e.g., "alice@example.com").
	Addr string `json:"email"`
	// Name is an optional display name (e.g., "Alice Smith").
	Name string `json:"name,omitzero"`
}

// NewAddress creates a new [Email] with an optional display name.
func NewAddress(addr, name string) Email {
	return Email{
		Addr: addr,
		Name: name,
	}
}

// String implements [fmt.Stringer] to return the string representation of the
// [Email] (e.g., "Name <email@example.com>").
func (e Email) String() string {
	if e.Name == "" {
		return e.Addr
	}
	return fmt.Sprintf("%s <%s>", e.Name, e.Addr)
}

// Recipient represents a single intended recipient or group of receivers,
// along with the specific template data to be used for them.
type Recipient struct {
	// To contains the primary [Email] recipients.
	To []Email `json:"to"`
	// CC contains the carbon copy [Email] recipients.
	CC []Email `json:"cc,omitzero"`
	// TemplateData holds the key-value pairs used to populate the template
	// variables for this specific recipient group.
	TemplateData map[string]any `json:"dynamic_template_data,omitzero"`
}

// NewRecipient creates a new [Recipient] group with the required primary
// destinations.
func NewRecipient(to ...Email) *Recipient {
	return &Recipient{
		To: to,
	}
}

// AddTo appends one or more [Email] recipients to the To list.
func (r *Recipient) AddTo(addrs ...Email) *Recipient {
	r.To = append(r.To, addrs...)
	return r
}

// AddCC appends one or more [Email] recipients to the CC list.
func (r *Recipient) AddCC(addrs ...Email) *Recipient {
	r.CC = append(r.CC, addrs...)
	return r
}

// AddTemplateData adds or updates a key-value pair in the TemplateData map.
func (r *Recipient) AddTemplateData(key string, value any) *Recipient {
	if r.TemplateData == nil {
		r.TemplateData = make(map[string]any)
	}
	r.TemplateData[key] = value
	return r
}

// SetTemplateData replaces the entire TemplateData map for the [Recipient].
func (r *Recipient) SetTemplateData(data map[string]any) *Recipient {
	r.TemplateData = data
	return r
}

// Validate checks if the [Recipient] group has at least one primary
// destination.
func (r *Recipient) Validate() error {
	if r == nil || len(r.To) == 0 {
		return ErrMissingRecipients
	}
	return nil
}

// Message represents a transactional email payload designed for dynamic
// templates.
type Message struct {
	// From is the sender's [Email] address.
	From Email `json:"from"`
	// Recipients contains groups of receivers and their specific template data.
	Recipients []*Recipient `json:"personalizations"`
	// ReplyTo is an optional [Email] address where replies should be directed.
	ReplyTo *Email `json:"reply_to,omitzero"`
	// TemplateID is the provider-specific identifier of the dynamic template to
	// use.
	TemplateID string `json:"template_id"`
}

// NewMessage creates a new [Message] with the required fields.
func NewMessage(
	from Email,
	templateID string,
	recipients ...*Recipient,
) *Message {
	return &Message{
		From:       from,
		TemplateID: templateID,
		Recipients: recipients,
	}
}

// AddRecipient appends a [Recipient] group to the [Message].
func (m *Message) AddRecipient(r *Recipient) *Message {
	m.Recipients = append(m.Recipients, r)
	return m
}

// WithReplyTo sets an optional ReplyTo [Email] address on the [Message].
func (m *Message) WithReplyTo(addr Email) *Message {
	m.ReplyTo = &addr
	return m
}

// Validate checks if the [Message] has the minimum required fields for sending.
func (m *Message) Validate() error {
	if m == nil {
		return ErrNilMessage
	}
	if m.From.Addr == "" {
		return ErrMissingFrom
	}
	if len(m.Recipients) == 0 {
		return ErrMissingRecipients
	}
	for _, r := range m.Recipients {
		if err := r.Validate(); err != nil {
			return err
		}
	}
	if m.TemplateID == "" {
		return ErrMissingTemplateID
	}
	return nil
}

// Sender is the interface that wraps the Send method.
//
// Implementations of this interface are expected to be safe for concurrent
// use by multiple goroutines. They should respect the provided context for
// timeouts and cancellation.
type Sender interface {
	// Send dispatches the provided [Message] payload to the underlying provider.
	// It returns an error if the email is invalid, if the network request
	// fails, or if the provider rejects the payload.
	Send(ctx context.Context, msg *Message) error
}

// sender is a SendGrid email client that implements the [Sender] interface.
//
// It manages the HTTP client and authentication state required to interact
// with the SendGrid API. Once initialized via [NewSender], a [sender] is safe
// for concurrent use by multiple goroutines.
type sender struct {
	// apiKey stores the authentication credential for the provider.
	apiKey string
	// url is the resolved API endpoint for dispatching requests.
	url string
	// client holds the configured HTTP client.
	client *http.Client
	// logger is used for structured diagnostic output.
	logger *slog.Logger
	// retry contains the retry configuration options.
	retry []retry.Option
}

var _ Sender = (*sender)(nil)

// config holds the optional configuration for the [sender].
type config struct {
	// client holds a custom HTTP client, if provided.
	client *http.Client
	// baseURL overrides the default SendGrid API endpoint.
	baseURL string
	// timeout sets the maximum duration for HTTP requests.
	timeout time.Duration
	// retry stores options for the HTTP transport retry mechanism.
	retry []retry.Option
	// logger specifies the custom structured logger.
	logger *slog.Logger
}

// Option defines the functional option pattern for configuring the [sender].
type Option func(*config)

// WithClient allows passing a custom HTTP client to the [sender].
// If provided, it overrides the [WithTimeout] setting.
func WithClient(client *http.Client) Option {
	return func(c *config) {
		if client != nil {
			c.client = client
		}
	}
}

// WithBaseURL allows overriding the SendGrid API base URL for testing or
// mocking.
func WithBaseURL(url string) Option {
	return func(c *config) {
		c.baseURL = url
	}
}

// WithTimeout configures the timeout for the default HTTP client.
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		c.timeout = d
	}
}

// WithRetryOptions configures the retry mechanism for the default HTTP client.
// If a custom HTTP client is provided via [WithClient], these options are
// ignored.
func WithRetryOptions(opts ...retry.Option) Option {
	return func(c *config) {
		c.retry = append(c.retry, opts...)
	}
}

// WithLogger injects a structured logger into the [sender].
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// NewSender creates a configured SendGrid client implementing the [Sender]
// interface.
//
// It initializes the client with a default base URL, a sensible timeout,
// and a standard logger. These defaults can be overridden by passing one or
// more [Option] functions. If no custom HTTP client is provided, it builds
// an internal client optimized for API calls with connection pooling and
// automatic retry capabilities. It panics if the API key is empty or the base
// URL is invalid.
func NewSender(apiKey string, opts ...Option) Sender {
	if apiKey == "" {
		panic("mail: API key is required")
	}

	cfg := config{
		baseURL: DefaultBaseURL,
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	endpoint, err := url.JoinPath(cfg.baseURL, "mail/send")
	if err != nil {
		panic(fmt.Errorf("mail: invalid base URL: %w", err))
	}

	s := &sender{
		apiKey: apiKey,
		url:    endpoint,
		logger: cfg.logger,
		retry:  cfg.retry,
	}

	// Initialize the default HTTP client if a custom one wasn't provided.
	if cfg.client == nil {
		d := &net.Dialer{
			Timeout: cfg.timeout / 3,
		}
		var t http.RoundTripper = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           d.DialContext,
			TLSHandshakeTimeout:   cfg.timeout / 3,
			ResponseHeaderTimeout: cfg.timeout * 9 / 10,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
		}
		t = retry.NewTransport(t, cfg.retry...)
		s.client = &http.Client{
			Timeout:   cfg.timeout,
			Transport: t,
		}
	} else {
		if len(cfg.retry) > 0 {
			cfg.logger.Warn("Custom client provided; retry options will be ignored")
		}
		s.client = cfg.client
	}

	return s
}

// Send executes the HTTP request to the SendGrid API.
//
// It maps the domain [Message] payload into SendGrid's expected JSON
// structure and dispatches the request. It respects the provided context
// for timeouts and cancellation. If the API responds with an HTTP status
// code >= 400, it logs the response body and returns an [*APIError].
func (s *sender) Send(ctx context.Context, msg *Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(msg); err != nil {
		return fmt.Errorf("mail: failed to encode payload: %w", err)
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		s.url,
		&buf,
	)
	if err != nil {
		return fmt.Errorf("mail: failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	s.logger.DebugContext(ctx, "Dispatching message to provider",
		slog.String("template_id", msg.TemplateID),
		slog.Int("recipients", len(msg.Recipients)),
	)

	start := time.Now()
	res, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("mail: request failed: %w", err)
	}
	delta := time.Since(start)

	defer func() {
		// Drain body to ensure connection reuse:
		_, _ = io.Copy(io.Discard, res.Body)
		err := res.Body.Close()
		if err != nil {
			s.logger.WarnContext(
				ctx,
				"Failed to close response body",
				slog.Any("error", err),
			)
		}
	}()

	if code := res.StatusCode; code >= 400 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		return &APIError{
			Status: code,
			Body:   string(body),
		}
	}

	s.logger.DebugContext(
		ctx,
		"Message successfully dispatched",
		slog.Duration("duration", delta),
	)

	return nil
}
