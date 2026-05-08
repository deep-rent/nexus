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
	"net/http"
	"time"

	"github.com/deep-rent/nexus/mail"
)

const defaultBaseURL = "https://api.sendgrid.com/v3"

var (
	// ErrMissingAPIKey is returned when the SendGrid API key is not provided.
	ErrMissingAPIKey = errors.New("sendgrid: missing API key")
	// ErrNilEmail is returned when a nil email is passed to Send.
	ErrNilEmail = errors.New("sendgrid: email cannot be nil")
	// ErrNoRecipients is returned when an email has no recipients.
	ErrNoRecipients = errors.New("sendgrid: at least one recipient is required")
)

// Client is a SendGrid email sender that implements mail.Sender.
type Client struct {
	apiKey     string
	baseURL    string
	timeout    time.Duration
	httpClient *http.Client
	logger     *slog.Logger
}

// Option defines the functional option pattern for configuring the Client.
type Option func(*Client)

// WithHTTPClient allows passing a custom HTTP client.
// If provided, it overrides the WithTimeout setting.
func WithHTTPClient(c *http.Client) Option {
	return func(client *Client) {
		if c != nil {
			client.httpClient = c
		}
	}
}

// WithBaseURL allows overriding the SendGrid API base URL for testing or mocking.
func WithBaseURL(url string) Option {
	return func(client *Client) {
		client.baseURL = url
	}
}

// WithTimeout configures the timeout for the default HTTP client.
func WithTimeout(d time.Duration) Option {
	return func(client *Client) {
		client.timeout = d
	}
}

// WithLogger injects a structured logger into the client.
func WithLogger(logger *slog.Logger) Option {
	return func(client *Client) {
		if logger != nil {
			client.logger = logger
		}
	}
}

// New creates a configured SendGrid client.
func New(apiKey string, opts ...Option) *Client {
	c := &Client{
		apiKey:  apiKey,
		baseURL: defaultBaseURL,
		timeout: 10 * time.Second, // Sensible default timeout
		logger:  slog.Default(),   // Fallback to standard structured logger
	}

	for _, opt := range opts {
		opt(c)
	}

	// Initialize the default HTTP client if a custom one wasn't provided
	if c.httpClient == nil {
		c.httpClient = &http.Client{
			Timeout: c.timeout,
		}
	}

	return c
}

// -- Internal API payload structures using v2 tags --

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
func (c *Client) Send(ctx context.Context, email *mail.Email) error {
	if c.apiKey == "" {
		return ErrMissingAPIKey
	}
	if email == nil {
		return ErrNilEmail
	}
	if len(email.To) == 0 {
		return ErrNoRecipients
	}

	p := c.buildPayload(email)

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

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sendgrid: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		c.logger.ErrorContext(ctx, "sendgrid API error",
			slog.Int("status_code", resp.StatusCode),
			slog.String("response", string(respBody)),
		)
		return fmt.Errorf("sendgrid: API error %d: %s", resp.StatusCode, string(respBody))
	}

	c.logger.DebugContext(ctx, "email successfully dispatched to sendgrid",
		slog.Int("status_code", resp.StatusCode),
	)

	return nil
}

// buildPayload maps the domain email model to the SendGrid JSON structure.
func (c *Client) buildPayload(email *mail.Email) payload {
	pers := personalization{
		To:                  buildAddresses(email.To),
		Cc:                  buildAddresses(email.Cc),
		Bcc:                 buildAddresses(email.Bcc),
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

// buildAddresses is a helper to convert domain addresses to internal addresses.
func buildAddresses(addrs []mail.Address) []address {
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
