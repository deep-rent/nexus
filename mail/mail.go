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
// provides a production-ready Twilio SendGrid implementation initialized via
// [NewSender].
//
// # Usage
//
// Typically, you initialize a [Sender] at application startup, construct
// a [Message] using the fluent API, and pass it to the sender.
//
// Example:
//
//	// 1. Initialize the default SendGrid sender with a custom User-Agent.
//	sender := mail.NewSender("your-api-key", mail.WithUserAgent("MyApp/1.0"))
//
//	// 2. Construct the email message.
//	msg := mail.NewMessage(
//	  mail.New("no-reply@example.com", "My App"),
//	  "template-id-123",
//	  mail.NewRecipient(mail.New("user@example.com", "Alice")).
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

const (
	// DefaultBaseURL is the standard API endpoint for SendGrid v3.
	DefaultBaseURL = "https://api.sendgrid.com/v3"
	// DefaultTimeout is the default timeout for API requests (5 seconds).
	DefaultTimeout = 5 * time.Second
)

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

// Error implements the [error] interface.
func (e *APIError) Error() string {
	return fmt.Sprintf("mail: api returned status %d: %s", e.Status, e.Body)
}

// Unwrap allows [errors.Is] to match against [ErrDispatchFailed].
func (e *APIError) Unwrap() error {
	return ErrDispatchFailed
}

var _ error = (*APIError)(nil)

// Mail represents an email address and an optional display name.
type Mail struct {
	// Addr is the actual email address (e.g., "alice@example.com").
	Addr string `json:"email"`
	// Name is an optional display name (e.g., "Alice Smith").
	Name string `json:"name,omitzero"`
}

// New creates a new [Mail] with an optional display name.
func New(addr, name string) Mail {
	return Mail{
		Addr: addr,
		Name: name,
	}
}

// String implements [fmt.Stringer] to return the string representation of the
// email instance (e.g., "Name <email@example.com>").
func (m Mail) String() string {
	if m.Name == "" {
		return m.Addr
	}
	return fmt.Sprintf("%s <%s>", m.Name, m.Addr)
}

// Recipient represents a single intended recipient or group of receivers,
// along with the specific template data to be used for them.
type Recipient struct {
	// To contains the primary [Mail] recipients.
	To []Mail `json:"to"`
	// CC contains the carbon copy [Mail] recipients.
	CC []Mail `json:"cc,omitzero"`
	// TemplateData holds the key-value pairs used to populate the template
	// variables for this specific recipient group.
	TemplateData map[string]any `json:"dynamic_template_data,omitzero"`
}

// NewRecipient creates a new [Recipient] group with the required primary
// destinations.
func NewRecipient(to ...Mail) *Recipient {
	return &Recipient{
		To: to,
	}
}

// AddTo appends one or more [Mail] recipients to the To list.
func (r *Recipient) AddTo(mails ...Mail) *Recipient {
	r.To = append(r.To, mails...)
	return r
}

// AddCC appends one or more [Mail] recipients to the CC list.
func (r *Recipient) AddCC(mails ...Mail) *Recipient {
	r.CC = append(r.CC, mails...)
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

// Validate checks if the [Recipient] group has at least one primary destination.
func (r *Recipient) Validate() error {
	if r == nil || len(r.To) == 0 {
		return ErrMissingRecipients
	}
	return nil
}

// Message represents a transactional email payload designed for dynamic
// templates.
type Message struct {
	// From is the sender's [Mail] address.
	From Mail `json:"from"`
	// Recipients contains groups of receivers and their specific template data.
	Recipients []*Recipient `json:"personalizations"`
	// ReplyTo is an optional [Mail] address where replies should be directed.
	ReplyTo *Mail `json:"reply_to,omitzero"`
	// TemplateID is the provider-specific identifier of the dynamic template to
	// use.
	TemplateID string `json:"template_id"`
}

// NewMessage creates a new [Message] with the required fields.
func NewMessage(
	from Mail,
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

// WithReplyTo sets an optional ReplyTo [Mail] address on the [Message].
func (m *Message) WithReplyTo(mail Mail) *Message {
	m.ReplyTo = &mail
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
	// auth stores the Authorization header value for the provider.
	auth string
	// url is the resolved API endpoint for dispatching requests.
	url string
	// userAgent is the value sent in the User-Agent header of requests.
	userAgent string
	// client holds the configured [http.Client].
	client *http.Client
	// logger is used for structured diagnostic output.
	logger *slog.Logger
	// retry contains the retry configuration options.
	retry []retry.Option
}

var _ Sender = (*sender)(nil)

// config holds the optional configuration for the [sender].
type config struct {
	// client holds a custom [http.Client], if provided.
	client *http.Client
	// baseURL overrides the default SendGrid API endpoint.
	baseURL string
	// userAgent defines the User-Agent header value for outgoing requests.
	userAgent string
	// timeout sets the maximum [time.Duration] for HTTP requests.
	timeout time.Duration
	// retry stores options for the HTTP transport retry mechanism.
	retry []retry.Option
	// logger specifies the custom structured [slog.Logger].
	logger *slog.Logger
}

// Option defines the functional option pattern for configuring the [sender].
type Option func(*config)

// WithClient allows passing a custom [http.Client] to the [sender].
// If provided, it overrides the [WithTimeout] setting. Nil values will be
// ignored.
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

// WithUserAgent configures a custom User-Agent header for the outbound
// API requests.
func WithUserAgent(v string) Option {
	return func(c *config) {
		c.userAgent = v
	}
}

// WithTimeout configures the timeout for the default [http.Client].
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

// WithLogger injects a structured [slog.Logger] into the sender.
// Nil values will be ignored.
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
// more [Option] functions. If no custom [http.Client] is provided, it builds
// an internal client optimized for API calls with connection pooling and
// automatic retry capabilities. It panics if the API key is empty or the base
// URL is invalid.
func NewSender(apiKey string, opts ...Option) Sender {
	if apiKey == "" {
		panic("mail: API key is required")
	}

	cfg := config{
		baseURL: DefaultBaseURL,
		timeout: DefaultTimeout,
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
		auth:      "Bearer " + apiKey,
		url:       endpoint,
		userAgent: cfg.userAgent,
		logger:    cfg.logger,
		retry:     cfg.retry,
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

// Send executes the HTTP request to the SendGrid v3 API.
//
// It maps the domain [Message] payload into SendGrid's expected JSON
// structure and dispatches the request. It respects the provided
// [context.Context] for timeouts and cancellation. If the API responds with
// an HTTP status code >= 400, it logs the response body and returns an
// [*APIError].
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

	req.Header.Set("Authorization", s.auth)

	if s.userAgent != "" {
		req.Header.Set("User-Agent", s.userAgent)
	}
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
		"Message dispatched",
		slog.Duration("duration", delta),
	)

	return nil
}
