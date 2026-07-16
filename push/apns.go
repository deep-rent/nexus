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

package push

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

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/retry"
	"github.com/deep-rent/nexus/sign"
	"github.com/deep-rent/nexus/token"
)

const (
	// APNSProductionURL is the production endpoint for APNs.
	APNSProductionURL = "https://api.push.apple.com"
	// APNSSandboxURL is the sandbox endpoint for APNs.
	APNSSandboxURL = "https://api.sandbox.push.apple.com"
)

type apns struct {
	source *token.Source
	url    string
	client *http.Client
	logger *slog.Logger
	retry  []retry.Option
}

var _ Sender = (*apns)(nil)

type apnsConfig struct {
	client  *http.Client
	baseURL string
	timeout time.Duration
	retry   []retry.Option
	logger  *slog.Logger
}

// APNSOption defines the functional option pattern for configuring the APNs sender.
type APNSOption func(*apnsConfig)

// WithAPNSClient allows passing a custom [http.Client] to the sender.
func WithAPNSClient(c *http.Client) APNSOption {
	return func(cfg *apnsConfig) {
		if c != nil {
			cfg.client = c
		}
	}
}

// WithAPNSBaseURL allows overriding the APNs API base URL.
// Useful for switching to [APNSSandboxURL] or mocking.
func WithAPNSBaseURL(url string) APNSOption {
	return func(cfg *apnsConfig) {
		cfg.baseURL = url
	}
}

// WithAPNSTimeout configures the timeout for the default HTTP client.
func WithAPNSTimeout(d time.Duration) APNSOption {
	return func(cfg *apnsConfig) {
		cfg.timeout = d
	}
}

// WithAPNSRetryOptions configures the retry mechanism for the default HTTP client.
func WithAPNSRetryOptions(opts ...retry.Option) APNSOption {
	return func(cfg *apnsConfig) {
		cfg.retry = append(cfg.retry, opts...)
	}
}

// WithAPNSLogger injects a structured [slog.Logger] into the sender.
func WithAPNSLogger(logger *slog.Logger) APNSOption {
	return func(cfg *apnsConfig) {
		if logger != nil {
			cfg.logger = logger
		}
	}
}

// APNS creates a configured Apple Push Notification Service client implementing
// the [Sender] interface. It requires the ES256 keyID, your Apple teamID, and
// the PEM-encoded PKCS#8 private key contents.
func APNS(keyID, teamID string, privateKeyPEM []byte, opts ...APNSOption) Sender {
	if keyID == "" || teamID == "" {
		panic("keyID and teamID are required")
	}
	signer, err := sign.Decode(privateKeyPEM)
	if err != nil {
		panic(fmt.Errorf("failed to parse APNs private key: %w", err))
	}

	keyPair := jwk.NewKeyPair(jwa.ES256, keyID, signer)

	cfg := apnsConfig{
		baseURL: APNSProductionURL,
		timeout: 5 * time.Second,
		logger:  slog.Default(),
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	fetch := func(ctx context.Context) (string, time.Time, error) {
		claims := struct {
			jwt.Reserved
		}{
			Reserved: jwt.Reserved{
				Iss: teamID,
				Iat: time.Now(),
			},
		}
		tok, err := jwt.Sign(ctx, keyPair, claims)
		if err != nil {
			return "", time.Time{}, err
		}
		// Apple allows tokens to be used between 20 and 60 minutes.
		return string(tok), time.Now().Add(45 * time.Minute), nil
	}

	source := token.NewSource(fetch, token.WithBufferTime(5*time.Minute))

	s := &apns{
		source: source,
		url:    cfg.baseURL,
		logger: cfg.logger,
		retry:  cfg.retry,
	}

	if cfg.client == nil {
		d := &net.Dialer{Timeout: cfg.timeout / 3}
		var t http.RoundTripper = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           d.DialContext,
			ForceAttemptHTTP2:     true, // APNs requires HTTP/2
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
			s.logger.Warn("Custom client provided; retry options will be ignored")
		}
		s.client = cfg.client
	}

	return s
}

// Send dispatches the HTTP/2 request to the APNs API.
func (s *apns) Send(ctx context.Context, msg *Message) error {
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
	for k, v := range msg.Data {
		payload[k] = v
	}
	payload["aps"] = map[string]any{
		"alert": map[string]any{
			"title": msg.Title,
			"body":  msg.Body,
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
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
	if msg.Target.Topic != "" {
		req.Header.Set("apns-topic", msg.Target.Topic)
	}
	req.Header.Set("apns-push-type", "alert")

	s.logger.DebugContext(ctx, "Dispatching APNs message", slog.String("token", msg.Target.Token))

	start := time.Now()
	res, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	delta := time.Since(start)

	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		if err := res.Body.Close(); err != nil {
			s.logger.WarnContext(ctx, "Failed to close response body", slog.Any("error", err))
		}
	}()

	if res.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		return &APIError{
			Status: res.StatusCode,
			Body:   string(body),
		}
	}

	s.logger.DebugContext(ctx, "APNs message dispatched", slog.Duration("duration", delta))
	return nil
}
