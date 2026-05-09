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

// Package sendgrid implements the [mail.Sender] interface using the
// SendGrid v3 Web API.
//
// It provides a robust HTTP client configured with sensible defaults,
// including timeouts, connection pooling, and automatic retries for
// transient network errors (via the retry package).
//
// # Usage
//
// Create a new Sender with your API key:
//
//	sender := sendgrid.New(
//		"SG.your.api.key",
//		sendgrid.WithTimeout(15 * time.Second),
//	)
//
//	err := sender.Send(ctx, email)
//
// If the SendGrid API returns an error status code, Send returns an
// [*APIError] which can be inspected for the specific HTTP status code
// and response body.
package sendgrid

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/deep-rent/nexus/mail"
	"github.com/deep-rent/nexus/retry"
)

// DefaultBaseURL is the standard API endpoint for SendGrid v3.
const DefaultBaseURL = "https://api.sendgrid.com/v3"

// ErrMissingAPIKey is returned when the SendGrid API key is not provided.
var ErrMissingAPIKey = errors.New("sendgrid: missing API key")

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

// Sender is a SendGrid email sender that implements [mail.Sender].
//
// It manages the HTTP client and authentication state required to interact
// with the SendGrid API. Once initialized via [New], a Sender is safe for
// concurrent use by multiple goroutines.
type Sender struct {
	apiKey    string
	baseURL   string
	timeout   time.Duration
	client    *http.Client
	logger    *slog.Logger
	retryOpts []retry.Option
}

// Option defines the functional option pattern for configuring the Client.
type Option func(*Sender)

// WithClient allows passing a custom HTTP client.
// If provided, it overrides the WithTimeout setting.
func WithClient(client *http.Client) Option {
	return func(s *Sender) {
		if client != nil {
			s.client = client
		}
	}
}

// WithBaseURL allows overriding the SendGrid API base URL for testing or
// mocking.
func WithBaseURL(url string) Option {
	return func(s *Sender) {
		s.baseURL = url
	}
}

// WithTimeout configures the timeout for the default HTTP client.
func WithTimeout(d time.Duration) Option {
	return func(s *Sender) {
		s.timeout = d
	}
}

// WithRetryOptions configures the retry mechanism for the default HTTP client.
// If a custom HTTP client is provided via WithHTTPClient, these options are
// ignored.
func WithRetryOptions(opts ...retry.Option) Option {
	return func(s *Sender) {
		s.retryOpts = append(s.retryOpts, opts...)
	}
}

// WithLogger injects a structured logger into the client.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Sender) {
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
func New(apiKey string, opts ...Option) *Sender {
	c := &Sender{
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
		t = retry.NewTransport(t, c.retryOpts...)
		c.client = &http.Client{
			Timeout:   c.timeout,
			Transport: t,
		}
	}

	return c
}

type personalization struct {
	To           []mail.Address `json:"to"`
	CC           []mail.Address `json:"cc,omitzero"`
	BCC          []mail.Address `json:"bcc,omitzero"`
	TemplateData map[string]any `json:"dynamic_template_data,omitzero"`
}

type payload struct {
	Personalizations []personalization `json:"personalizations"`
	From             mail.Address      `json:"from"`
	ReplyTo          *mail.Address     `json:"reply_to,omitzero"`
	TemplateID       string            `json:"template_id"`
}

// Send executes the HTTP request to the SendGrid API.
//
// It maps the domain [mail.Email] payload into SendGrid's expected JSON
// structure and dispatches the request. It respects the provided context
// for timeouts and cancellation. If the API responds with an HTTP status
// code >= 400, it returns an [*APIError] containing the raw response body.
func (c *Sender) Send(ctx context.Context, email *mail.Email) error {
	if c.apiKey == "" {
		return ErrMissingAPIKey
	}
	if err := email.Validate(); err != nil {
		return err
	}

	p := c.payload(email)

	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("sendgrid: failed to marshal payload: %w", err)
	}

	url := c.baseURL + "/mail/send"
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		url,
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("sendgrid: failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	c.logger.DebugContext(ctx, "Sending email via SendGrid",
		slog.String("template_id", email.TemplateID),
		slog.String("url", url),
	)

	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("sendgrid: request failed: %w", err)
	}
	defer func() {
		err := res.Body.Close()
		if err != nil {
			c.logger.WarnContext(
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

	c.logger.DebugContext(ctx, "Email successfully dispatched to SendGrid",
		slog.Int("status_code", res.StatusCode),
	)

	return nil
}

// payload maps the domain email model to the SendGrid JSON structure.
func (c *Sender) payload(email *mail.Email) payload {
	pers := make([]personalization, 0, len(email.Recipients))
	for _, r := range email.Recipients {
		pers = append(pers, personalization{
			To:           r.To,
			CC:           r.CC,
			BCC:          r.BCC,
			TemplateData: r.TemplateData,
		})
	}

	p := payload{
		Personalizations: pers,
		From:             email.From,
		TemplateID:       email.TemplateID,
	}

	if email.ReplyTo != nil {
		p.ReplyTo = email.ReplyTo
	}

	return p
}
