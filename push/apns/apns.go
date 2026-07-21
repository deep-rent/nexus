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

package apns

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/push"
	"github.com/deep-rent/nexus/sign"
	"github.com/deep-rent/nexus/token"
	"github.com/deep-rent/nexus/transport"
)

const (
	// DefaultBaseURL is the production endpoint for APNs.
	DefaultBaseURL = "https://api.push.apple.com"
	// SandboxBaseURL is the sandbox endpoint for APNs.
	SandboxBaseURL = "https://api.sandbox.push.apple.com"
)

// Sender implements the [push.Sender] interface for the Apple Push Notification
// service (APNs). It handles authentication, payload construction, and
// dispatching of push notifications to APNs endpoints.
type Sender struct {
	source *token.Source
	url    string
	topic  string
	client *http.Client
	logger *slog.Logger
	clock  func() time.Time
}

var _ push.Sender = (*Sender)(nil)

type config struct {
	baseURL string
	topic   string
	logger  *slog.Logger
	now     func() time.Time
	client  *http.Client
}

// Option defines the functional option pattern for configuring the APNs sender.
type Option func(*config)

// WithClient sets the [http.Client] used for outbound API requests. Defaults
// to [transport.DefaultClient]. Nil values are ignored.
func WithClient(client *http.Client) Option {
	return func(cfg *config) {
		if client != nil {
			cfg.client = client
		}
	}
}

// WithBaseURL allows overriding the APNs API base URL.
// Useful for switching to [SandboxBaseURL] or mocking.
// Empty string values are ignored.
func WithBaseURL(url string) Option {
	return func(cfg *config) {
		if url != "" {
			cfg.baseURL = url
		}
	}
}

// WithTopic sets the default apns-topic header, which is the app's bundle
// identifier (optionally with a type suffix such as ".voip"). APNs requires it
// for most push types, so it is normally configured once here rather than per
// message. A message may still override it via [push.Target.Topic]. Empty
// string values are ignored.
func WithTopic(topic string) Option {
	return func(cfg *config) {
		if topic != "" {
			cfg.topic = topic
		}
	}
}

// WithLogger injects a structured [slog.Logger] into the sender.
// Nil values are ignored.
func WithLogger(logger *slog.Logger) Option {
	return func(cfg *config) {
		if logger != nil {
			cfg.logger = logger
		}
	}
}

// WithClock injects a custom clock function for JWT generation and caching.
// Nil values are ignored.
func WithClock(now func() time.Time) Option {
	return func(cfg *config) {
		if now != nil {
			cfg.now = now
		}
	}
}

// Credentials contains the necessary credentials for authenticating with APNs.
type Credentials struct {
	// KeyID specifies the ES256 key ID from your Apple Developer account.
	KeyID string
	// TeamID is your Apple team ID.
	TeamID string
	// PrivateKey stores the PEM-encoded PKCS#8 private key contents.
	PrivateKey []byte
}

// New creates a configured Apple Push Notification Service client implementing
// the [push.Sender] interface. It requires the ES256 keyID, your Apple teamID,
// and the PEM-encoded PKCS#8 private key contents. Requests are dispatched
// through [transport.DefaultClient] unless [WithClient] provides another one;
// note that any such client must support HTTP/2.
func New(
	cred Credentials,
	opts ...Option,
) push.Sender {
	signer, err := sign.Decode(cred.PrivateKey)
	if err != nil {
		panic(fmt.Errorf("failed to parse APNs private key: %w", err))
	}

	key := jwk.NewKeyPair(jwa.ES256, cred.KeyID, signer)

	cfg := config{
		baseURL: DefaultBaseURL,
		logger:  slog.Default(),
		now:     time.Now,
		client:  transport.DefaultClient,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	fetch := func(ctx context.Context) (string, time.Time, error) {
		claims := struct {
			jwt.Reserved
		}{
			Iss: cred.TeamID,
			Iat: cfg.now(),
		}
		tok, err := jwt.Sign(ctx, key, claims)
		if err != nil {
			return "", time.Time{}, err
		}
		// Apple allows tokens to be used between 20 and 60 minutes so we
		// settle in the middle.
		return string(tok), cfg.now().Add(45 * time.Minute), nil
	}

	source := token.NewSource(
		fetch,
		token.WithBufferTime(5*time.Minute),
		token.WithClock(cfg.now),
	)

	s := &Sender{
		source: source,
		url:    cfg.baseURL,
		topic:  cfg.topic,
		logger: cfg.logger,
		client: cfg.client,
		clock:  cfg.now,
	}

	return s
}

// Send dispatches the HTTP/2 request to the APNs API.
func (s *Sender) Send(ctx context.Context, msg *push.Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	if msg.Target.Token == "" {
		return errors.New("APNs requires a device token target")
	}

	tok, err := s.source.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get APNs token: %w", err)
	}

	payload := make(map[string]any)
	maps.Copy(payload, msg.Data)
	aps := make(map[string]any)
	if msg.Silent {
		aps["content-available"] = 1
	} else {
		aps["alert"] = map[string]any{
			"title": msg.Title,
			"body":  msg.Body,
		}
	}
	payload["aps"] = aps

	var buf bytes.Buffer
	if err := json.MarshalWrite(&buf, payload); err != nil {
		return fmt.Errorf("failed to encode APNs payload: %w", err)
	}

	endpoint, err := url.JoinPath(s.url, "3/device", msg.Target.Token)
	if err != nil {
		return fmt.Errorf("invalid endpoint: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "bearer "+tok)
	req.Header.Set("Content-Type", "application/json")

	// A per-message topic overrides the sender's configured default.
	topic := s.topic
	if msg.Target.Topic != "" {
		topic = msg.Target.Topic
	}
	if topic != "" {
		req.Header.Set("apns-topic", topic)
	}

	if msg.Silent {
		req.Header.Set("apns-push-type", "background")
		req.Header.Set("apns-priority", "5")
	} else {
		req.Header.Set("apns-push-type", "alert")
		if msg.Priority == push.PriorityNormal {
			req.Header.Set("apns-priority", "5")
		} else {
			req.Header.Set("apns-priority", "10") // Default for alert
		}
	}

	if msg.CollapseID != "" {
		req.Header.Set("apns-collapse-id", msg.CollapseID)
	}

	if msg.TTL > 0 {
		exp := s.clock().Add(msg.TTL).Unix()
		req.Header.Set("apns-expiration", strconv.FormatInt(exp, 10))
	} else {
		req.Header.Set("apns-expiration", "0")
	}

	s.logger.DebugContext(
		ctx,
		"Dispatching APNs message",
		slog.String("token", msg.Target.Token),
	)

	return push.Deliver(ctx, s.client, req, s.logger)
}
