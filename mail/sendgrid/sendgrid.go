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

// Package sendgrid implements the mail.Sender interface for the SendGrid v3
// API.
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

const DefaultBaseURL = "https://api.sendgrid.com/v3"

// ErrMissingAPIKey is returned when the SendGrid API key is not provided.
var ErrMissingAPIKey = errors.New("sendgrid: missing API key")

// APIError represents an error response from the SendGrid API.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("sendgrid: API error %d: %s", e.StatusCode, e.Body)
}

// Sender is a SendGrid email sender that implements mail.Sender.
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

type address struct {
	Email string `json:"email"`
	Name  string `json:"name,omitzero"`
}

type personalization struct {
	To                  []address      `json:"to"`
	Cc                  []address      `json:"cc,omitzero"`
	Bcc                 []address      `json:"bcc,omitzero"`
	DynamicTemplateData map[string]any `json:"dynamic_template_data,omitzero"`
}

type payload struct {
	Personalizations []personalization `json:"personalizations"`
	From             address           `json:"from"`
	ReplyTo          *address          `json:"reply_to,omitzero"`
	TemplateID       string            `json:"template_id"`
}

// Send executes the HTTP request to the SendGrid API.
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

	endpoint := fmt.Sprintf("%s/mail/send", c.baseURL)
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("sendgrid: failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	c.logger.DebugContext(ctx, "sending email via sendgrid",
		slog.String("template_id", email.TemplateID),
		slog.String("endpoint", endpoint),
	)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("sendgrid: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		err := &APIError{StatusCode: resp.StatusCode, Body: string(body)}
		c.logger.ErrorContext(ctx, "sendgrid API error",
			slog.Int("status_code", err.StatusCode),
			slog.String("response", err.Body),
		)
		return err
	}

	c.logger.DebugContext(ctx, "email successfully dispatched to sendgrid",
		slog.Int("status_code", resp.StatusCode),
	)

	return nil
}

// payload maps the domain email model to the SendGrid JSON structure.
func (c *Sender) payload(email *mail.Email) payload {
	pers := personalization{
		To:                  addresses(email.To),
		Cc:                  addresses(email.Cc),
		Bcc:                 addresses(email.Bcc),
		DynamicTemplateData: email.TemplateData,
	}

	p := payload{
		Personalizations: []personalization{pers},
		From: address{
			Email: email.From.Address,
			Name:  email.From.Name,
		},
		TemplateID: email.TemplateID,
	}

	if email.ReplyTo != nil {
		p.ReplyTo = &address{
			Email: email.ReplyTo.Address,
			Name:  email.ReplyTo.Name,
		}
	}

	return p
}

// addresses is a helper to convert domain addresses to internal addresses.
func addresses(addrs []mail.Address) []address {
	if len(addrs) == 0 {
		return nil
	}

	out := make([]address, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, address{
			Email: addr.Address,
			Name:  addr.Name,
		})
	}
	return out
}
