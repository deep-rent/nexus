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

package sms

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/nexus/transport"
)

const (
	// DefaultBaseURL is the standard API endpoint for Twilio Messaging.
	DefaultBaseURL = "https://api.twilio.com/2010-04-01"
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
	// Status is the HTTP status code returned by the provider. It is taken
	// from the response status line, not the body, so it is never populated
	// by unmarshaling.
	Status int `json:"-"`
	// Code is the Twilio-specific error code.
	Code int `json:"code"`
	// Message is the description of the error.
	Message string `json:"message"`
	// URL is a URL to more information about the error.
	URL string `json:"more_info"`
}

// Error implements the [error] interface.
func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf(
			"api returned status %d (code %d): %s",
			e.Status,
			e.Code,
			e.Message,
		)
	}
	return fmt.Sprintf("api returned status %d", e.Status)
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
	// sid is the Twilio Account SID used for authentication.
	sid string
	// token is the Twilio Auth Token used for authentication.
	token string
	// url is the resolved API endpoint for dispatching requests.
	url string
	// client holds the configured [http.Client].
	client *http.Client
	// logger is used for structured diagnostic output.
	logger *slog.Logger
}

var _ Sender = (*sender)(nil)

// config holds the optional configuration for the [sender].
type config struct {
	// baseURL overrides the default Twilio API endpoint.
	baseURL string
	// logger specifies the custom structured [slog.Logger].
	logger *slog.Logger
	// client is the HTTP client used for outbound API requests.
	client *http.Client
}

// Option defines the functional option pattern for configuring the [sender].
type Option func(*config)

// WithClient sets the [http.Client] used for outbound API requests. Defaults
// to [transport.DefaultClient]. Nil values are ignored.
func WithClient(client *http.Client) Option {
	return func(c *config) {
		if client != nil {
			c.client = client
		}
	}
}

// WithBaseURL allows overriding the Twilio API base URL for testing or mocking.
// Empty string values are ignored.
func WithBaseURL(url string) Option {
	return func(c *config) {
		if url != "" {
			c.baseURL = url
		}
	}
}

// WithLogger injects a structured [slog.Logger] into the sender.
// Nil values are ignored.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// NewSender creates a configured Twilio client with the given account SID and
// authentication token. Requests are dispatched through
// [transport.DefaultClient] unless [WithClient] provides another one.
func NewSender(sid, token string, opts ...Option) Sender {
	if sid == "" {
		panic("account SID is required")
	}
	if token == "" {
		panic("authentication token is required")
	}

	cfg := config{
		baseURL: DefaultBaseURL,
		logger:  slog.Default(),
		client:  transport.DefaultClient,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	endpoint, err := url.JoinPath(
		cfg.baseURL, "Accounts", sid, "Messages.json",
	)
	if err != nil {
		panic(fmt.Errorf("invalid base URL: %w", err))
	}

	s := &sender{
		sid:    sid,
		token:  token,
		url:    endpoint,
		logger: cfg.logger,
		client: cfg.client,
	}

	return s
}

// Send executes the HTTP request to the Twilio Messaging API.
// It returns an [APIError] when the API responds with an error status.
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

	req.SetBasicAuth(s.sid, s.token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	s.logger.DebugContext(
		ctx,
		"Dispatching SMS to provider",
		slog.String("to", msg.To),
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
		if err := res.Body.Close(); err != nil {
			s.logger.WarnContext(
				ctx,
				"Failed to close response body",
				log.Err(err),
			)
		}
	}()

	if code := res.StatusCode; code >= http.StatusBadRequest {
		var apiErr APIError
		apiErr.Status = code
		// Attempt to parse the JSON error body. If it fails, we just return the
		// status. The client caps response body size, so this read is bounded.
		if err := json.UnmarshalRead(res.Body, &apiErr); err != nil {
			s.logger.WarnContext(
				ctx,
				"Failed to parse API error response",
				log.Err(err),
			)
		}
		return &apiErr
	}

	s.logger.DebugContext(
		ctx,
		"SMS dispatched",
		slog.Duration("duration", delta),
	)

	return nil
}
