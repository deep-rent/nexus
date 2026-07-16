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
	"sync"
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
// Exactly one field should be populated.
type Target struct {
	// Token is a specific device identifier.
	Token string
	// Topic is a publish-subscribe channel identifier.
	Topic string
}

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
// [Sender]. It limits concurrency to the given workers limit to prevent
// exhausting system resources. The returned slice of errors corresponds
// exactly to the input messages slice index, containing nil for successful
// deliveries and the respective error for failures.
func BatchSend(
	ctx context.Context,
	sender Sender,
	msgs []*Message,
	workers int,
) []error {
	n := len(msgs)
	if n == 0 {
		return nil
	}
	workers = max(1, min(workers, n))

	errs := make([]error, n)
	var wg sync.WaitGroup

	jobs := make(chan int, n)
	for i := range msgs {
		jobs <- i
	}
	close(jobs)

	for w := 0; w < workers; w++ {
		wg.Go(func() {
			for i := range jobs {
				if err := ctx.Err(); err != nil {
					errs[i] = err
					continue
				}
				errs[i] = sender.Send(ctx, msgs[i])
			}
		})
	}

	wg.Wait()
	return errs
}
