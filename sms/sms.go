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

// Package sms provides abstractions for sending SMS messages via Twilio.
//
// It defines a generic payload model ([Message]) and a common [Sender]
// interface for SMS delivery, decoupling business logic from the underlying
// mechanism.
package sms

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deep-rent/nexus/retry"
)

const (
	// DefaultBaseURL is the standard API endpoint for Twilio Messaging.
	DefaultBaseURL = "https://api.twilio.com/2010-04-01"
	// DefaultTimeout is the default timeout for API requests (5 seconds).
	DefaultTimeout = 5 * time.Second
)

var (
	// ErrNilMessage is returned when a nil [Message] is validated.
	ErrNilMessage = errors.New("message cannot be nil")
	// ErrMissingTo is returned when an SMS has no destination number.
	ErrMissingTo = errors.New("to number is needed")
	// ErrMissingFrom is returned when an SMS has no sender number.
	ErrMissingFrom = errors.New("from number is needed")
	// ErrMissingBody is returned when an SMS has no text body.
	ErrMissingBody = errors.New("body is needed")
	// ErrDispatchFailed is returned when the underlying provider rejects the
	// payload.
	ErrDispatchFailed = errors.New("dispatching failed")
)

// APIError represents an error returned by the underlying SMS provider.
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

// Message represents a transactional SMS payload.
type Message struct {
	// To is the destination phone number.
	To string
	// From is the sender phone number or messaging service SID.
	From string
	// Body is the text content of the SMS.
	Body string
}

// NewMessage creates a new [Message] with the required fields.
func NewMessage(to, from, body string) *Message {
	return &Message{
		To:   to,
		From: from,
		Body: body,
	}
}

// Validate checks if the [Message] has the minimum required fields for sending.
func (m *Message) Validate() error {
	if m == nil {
		return ErrNilMessage
	}
	if m.To == "" {
		return ErrMissingTo
	}
	if m.From == "" {
		return ErrMissingFrom
	}
	if m.Body == "" {
		return ErrMissingBody
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
	// provider. It returns an error if the SMS is invalid, if the network
	// request fails, or if the provider rejects the payload.
	Send(ctx context.Context, msg *Message) error
}

// sender is a Twilio SMS client that implements the [Sender] interface.
type sender struct {
	// accountSID is the Twilio Account SID used for authentication.
	accountSID string
	// authToken is the Twilio Auth Token used for authentication.
	authToken string
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
	// baseURL overrides the default Twilio API endpoint.
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

// WithBaseURL allows overriding the Twilio API base URL for testing or mocking.
func WithBaseURL(url string) Option {
	return func(c *config) {
		c.baseURL = url
	}
}

// WithUserAgent configures a custom User-Agent header for the outbound API
// requests.
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
func WithRetryOptions(opts ...retry.Option) Option {
	return func(c *config) {
		c.retry = append(c.retry, opts...)
	}
}

// WithLogger injects a structured [slog.Logger] into the sender.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// NewSender creates a configured Twilio client implementing the [Sender]
// interface.
func NewSender(accountSID, authToken string, opts ...Option) Sender {
	if accountSID == "" {
		panic("Account SID is required")
	}
	if authToken == "" {
		panic("Auth Token is required")
	}

	cfg := config{
		baseURL: DefaultBaseURL,
		timeout: DefaultTimeout,
		logger:  slog.Default(),
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	endpoint, err := url.JoinPath(
		cfg.baseURL, "Accounts", accountSID, "Messages.json",
	)
	if err != nil {
		panic(fmt.Errorf("invalid base URL: %w", err))
	}

	s := &sender{
		accountSID: accountSID,
		authToken:  authToken,
		url:        endpoint,
		userAgent:  cfg.userAgent,
		logger:     cfg.logger,
		retry:      cfg.retry,
	}

	if cfg.client == nil {
		d := &net.Dialer{
			Timeout: cfg.timeout / 3,
		}
		var t http.RoundTripper = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           d.DialContext,
			TLSHandshakeTimeout:   cfg.timeout / 3,
			ResponseHeaderTimeout: cfg.timeout * 9 / 10,
			ExpectContinueTimeout: 1 * time.Second,
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
		if len(cfg.retry) != 0 {
			s.logger.Warn(
				"Custom client provided; retry options will be ignored",
			)
		}
		s.client = cfg.client
	}

	return s
}

// Send executes the HTTP request to the Twilio Messaging API.
func (s *sender) Send(ctx context.Context, msg *Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}

	data := url.Values{}
	data.Set("To", msg.To)
	data.Set("From", msg.From)
	data.Set("Body", msg.Body)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		s.url,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(s.accountSID, s.authToken)

	if s.userAgent != "" {
		req.Header.Set("User-Agent", s.userAgent)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	s.logger.DebugContext(ctx, "Dispatching SMS to provider",
		slog.String("to", msg.To),
	)

	start := time.Now()
	res, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	delta := time.Since(start)

	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		if err := res.Body.Close(); err != nil {
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
		"SMS dispatched",
		slog.Duration("duration", delta),
	)

	return nil
}

var _ Sender = (*sender)(nil)
