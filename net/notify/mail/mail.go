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

package mail

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/net/transport"
)

const (
	// DefaultBaseURL is the standard API endpoint for SendGrid v3.
	DefaultBaseURL = "https://api.sendgrid.com/v3"
)

var (
	// ErrNilMessage is returned when a nil [Message] is validated.
	ErrNilMessage = errors.New("message cannot be nil")
	// ErrMissingRecipients is returned when an email has no recipients.
	ErrMissingRecipients = errors.New("at least one recipient is needed")
	// ErrMissingTemplateID is returned when an email has no template ID.
	ErrMissingTemplateID = errors.New("template ID is needed")
	// ErrMissingFrom is returned when an email has no sender address.
	ErrMissingFrom = errors.New("from address is needed")
	// ErrDispatchFailed is returned when the underlying provider rejects the
	// payload.
	ErrDispatchFailed = errors.New("dispatching failed")
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
	return fmt.Sprintf("api returned status %d: %s", e.Status, e.Body)
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
	// Send dispatches the provided [Message] payload to the underlying
	// provider. It returns an error if the email is invalid, if the network
	// request fails, or if the provider rejects the payload.
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
}

var _ Sender = (*sender)(nil)


// NewSender creates a configured SendGrid client implementing the [Sender]
// interface.
//
// It initializes the client with a default base URL and a standard logger.
// These defaults can be overridden by passing one or more [Option] functions.
// Requests are dispatched through [transport.DefaultClient], which applies a
// sensible timeout, unless [WithClient] provides another one. It panics if the
// API key is empty or the base URL is invalid.
func NewSender(apiKey string, opts ...Option) Sender {
	if apiKey == "" {
		panic("API key is required")
	}

	cfg := config{
		baseURL: DefaultBaseURL,
		logger:  slog.Default(),
		client:  transport.DefaultClient,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	endpoint, err := url.JoinPath(cfg.baseURL, "mail/send")
	if err != nil {
		panic(fmt.Errorf("invalid base URL: %w", err))
	}

	s := &sender{
		auth:      "Bearer " + apiKey,
		url:       endpoint,
		userAgent: cfg.userAgent,
		logger:    cfg.logger,
		client:    cfg.client,
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
	if err := json.MarshalWrite(&buf, msg); err != nil {
		return fmt.Errorf("failed to encode payload: %w", err)
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		s.url,
		&buf,
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
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
		return fmt.Errorf("request failed: %w", err)
	}
	delta := time.Since(start)

	defer func() {
		if _, err := io.Copy(io.Discard, res.Body); err != nil {
			s.logger.WarnContext(
				ctx,
				"Failed to drain response body",
				log.Err(err),
			)
		}
		err := res.Body.Close()
		if err != nil {
			s.logger.WarnContext(
				ctx,
				"Failed to close response body",
				log.Err(err),
			)
		}
	}()

	if code := res.StatusCode; code >= 400 {
		// The client caps response body size, so this read is bounded.
		body, _ := io.ReadAll(res.Body)
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
