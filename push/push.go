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

// Package push provides abstractions for sending mobile push notifications.
//
// It defines a generic payload model ([Message]) and a common [Sender]
// interface for delivery via APNs (Apple) or FCM (Firebase/Android).
//
// # Usage
//
// Create messages with [NewMessage], optionally attach custom key-value pairs
// via [Message.WithData], and dispatch them through your concrete [Sender]
// implementation.
//
//	msg := push.NewMessage(
//		"New Match!",
//		"Someone liked your profile.",
//		push.Target{Token: "device_token_here"},
//	).WithData(map[string]any{"match_id": 123})
//
//	err := sender.Send(ctx, msg)
package push

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/deep-rent/nexus/log"
)

var (
	// ErrNilMessage is returned when a nil [Message] is validated.
	ErrNilMessage = errors.New("message cannot be nil")
	// ErrMissingTarget is returned when a push notification has no destination.
	ErrMissingTarget = errors.New("a target (token or topic) is needed")
	// ErrDispatchFailed is returned when the underlying provider rejects the
	// payload.
	ErrDispatchFailed = errors.New("dispatching failed")
)

// APIError represents an error returned by the underlying push provider.
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

// Target identifies the destination of the push notification.
//
// The two providers interpret it differently, since their delivery models
// differ:
//
//   - FCM delivers either to a device Token or to a publish-subscribe Topic,
//     so exactly one of the two should be set.
//   - APNs delivers only to a device Token; it has no publish-subscribe
//     topics. There, Topic instead overrides the "apns-topic" header (the
//     app's bundle identifier, possibly with a type suffix) for that one
//     message, and is normally left empty in favor of the sender's configured
//     topic.
type Target struct {
	// Token is a specific device identifier.
	Token string
	// Topic is a publish-subscribe channel (FCM) or an apns-topic override
	// (APNs); see the type documentation.
	Topic string
}

// Priority indicates the delivery priority of a message.
type Priority string

const (
	// PriorityNormal indicates the message is delivered when the device is
	// awake.
	PriorityNormal Priority = "normal"
	// PriorityHigh indicates the message should be delivered immediately.
	PriorityHigh Priority = "high"
)

// Message represents a generic push notification payload.
type Message struct {
	// Title is the short heading of the notification.
	Title string
	// Body is the main text content of the notification.
	Body string
	// Data contains optional custom key-value pairs delivered to the app.
	Data map[string]any
	// Target is the destination of the message.
	Target Target
	// Priority is the delivery urgency of the message.
	Priority Priority
	// CollapseID is an identifier used to replace existing notifications.
	CollapseID string
	// TTL is the time-to-live for the message.
	TTL time.Duration
	// Silent indicates whether the message is a background push.
	Silent bool
}

// NewMessage creates a new [Message] with the required fields.
func NewMessage(title, body string, target Target) *Message {
	return &Message{
		Title:  title,
		Body:   body,
		Target: target,
	}
}

// WithData adds custom data to the [Message].
func (m *Message) WithData(data map[string]any) *Message {
	m.Data = data
	return m
}

// WithPriority sets the delivery priority.
func (m *Message) WithPriority(p Priority) *Message {
	m.Priority = p
	return m
}

// WithCollapseID sets the collapse identifier.
func (m *Message) WithCollapseID(id string) *Message {
	m.CollapseID = id
	return m
}

// WithTTL sets the message expiration duration.
func (m *Message) WithTTL(ttl time.Duration) *Message {
	m.TTL = ttl
	return m
}

// AsSilent marks the message as a background push.
func (m *Message) AsSilent() *Message {
	m.Silent = true
	return m
}

// Validate checks if the [Message] has the minimum required fields.
func (m *Message) Validate() error {
	if m == nil {
		return ErrNilMessage
	}
	if m.Target.Token == "" && m.Target.Topic == "" {
		return ErrMissingTarget
	}
	return nil
}

// Sender represents a push notification provider.
//
// Implementations of this interface are expected to be safe for concurrent
// use by multiple goroutines. They should respect the provided context for
// timeouts and cancellation.
type Sender interface {
	// Send dispatches the provided [Message] payload to the underlying
	// provider.
	Send(ctx context.Context, msg *Message) error
}

// BatchSend concurrently dispatches multiple messages using the provided
// [Sender], with at most workers sends in flight at once.
//
// It is best-effort: a failure delivering one message does not abort the
// others, since a single dead token should not hold back an entire broadcast.
// Every message is attempted (unless the context is already cancelled by the
// time its turn comes), and the individual errors are collected and returned
// as a single joined error, nil if every send succeeded. Use [errors.Is] to
// probe it. To learn which specific messages failed, dispatch them
// individually or wrap [Sender.Send].
//
// Cancelling ctx stops further sends from starting and is observed by those
// already in flight, but does not itself count as a batch failure beyond the
// context errors recorded for the messages it prevented.
func BatchSend(
	ctx context.Context,
	sender Sender,
	msgs []*Message,
	workers int,
) error {
	n := len(msgs)
	if n == 0 {
		return nil
	}
	workers = max(1, min(workers, n))

	errs := make([]error, n)
	var eg errgroup.Group
	eg.SetLimit(workers)

	for i, msg := range msgs {
		eg.Go(func() error {
			// A cancelled context skips the remaining sends without
			// attempting them, rather than aborting the batch outright.
			if err := ctx.Err(); err != nil {
				errs[i] = err
				return nil
			}
			errs[i] = sender.Send(ctx, msg)
			return nil
		})
	}

	_ = eg.Wait()
	return errors.Join(errs...)
}

// Deliver executes req against client and interprets the response for a
// [Sender], returning nil on a success status or an [*APIError] carrying the
// status and body on a failure status (400 or above).
//
// It is the shared response-handling path for the built-in providers, exported
// so that a custom [Sender] can report failures with the same error shape. The
// response body is always drained and closed so the underlying connection can
// be reused.
func Deliver(
	ctx context.Context,
	client *http.Client,
	req *http.Request,
	logger *slog.Logger,
) error {
	start := time.Now()
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}

	defer func() {
		if _, err := io.Copy(io.Discard, res.Body); err != nil {
			logger.WarnContext(ctx, "Failed to drain response body", log.Err(err))
		}
		if err := res.Body.Close(); err != nil {
			logger.WarnContext(ctx, "Failed to close response body", log.Err(err))
		}
	}()

	logger.DebugContext(ctx, "Provider responded",
		slog.Int("status", res.StatusCode),
		slog.Duration("duration", time.Since(start)),
	)

	if res.StatusCode >= http.StatusBadRequest {
		// The client caps response body size, so this read is bounded.
		body, err := io.ReadAll(res.Body)
		if err != nil {
			logger.WarnContext(ctx, "Failed to read response body", log.Err(err))
		}
		return &APIError{Status: res.StatusCode, Body: string(body)}
	}

	return nil
}
