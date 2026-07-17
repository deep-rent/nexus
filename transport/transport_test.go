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

package transport

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/retry"
)

func TestNewClient_Defaults(t *testing.T) {
	client := NewClient()

	if client.Timeout != 5*time.Second {
		t.Errorf("expected default timeout to be 5s, got %v", client.Timeout)
	}

	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf(
			"expected transport to be *http.Transport, got %T",
			client.Transport,
		)
	}

	if tr.DisableKeepAlives {
		t.Error("expected DisableKeepAlives to be false by default")
	}

	if tr.ForceAttemptHTTP2 {
		t.Error("expected ForceAttemptHTTP2 to be false by default")
	}

	if tr.TLSClientConfig != nil {
		t.Error("expected TLSClientConfig to be nil by default")
	}

	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("expected TLSHandshakeTimeout to be 10s, got %v", tr.TLSHandshakeTimeout)
	}

	if tr.ExpectContinueTimeout != 1*time.Second {
		t.Errorf("expected ExpectContinueTimeout to be 1s, got %v", tr.ExpectContinueTimeout)
	}

	if tr.IdleConnTimeout != 90*time.Second {
		t.Errorf("expected IdleConnTimeout to be 90s, got %v", tr.IdleConnTimeout)
	}

	if tr.MaxIdleConns != 100 {
		t.Errorf("expected MaxIdleConns to be 100, got %d", tr.MaxIdleConns)
	}

	if tr.MaxIdleConnsPerHost != 100 {
		t.Errorf("expected MaxIdleConnsPerHost to be 100, got %d", tr.MaxIdleConnsPerHost)
	}
}

func TestNewClient_WithOptions(t *testing.T) {
	tlsCfg := &tls.Config{InsecureSkipVerify: true}

	client := NewClient(
		WithTimeout(10*time.Second),
		WithDialTimeout(15*time.Second),
		WithKeepAlive(16*time.Second),
		WithTLSHandshakeTimeout(17*time.Second),
		WithExpectContinueTimeout(18*time.Second),
		WithIdleConnTimeout(19*time.Second),
		WithTLSConfig(tlsCfg),
		WithDisableKeepAlives(true),
		WithForceAttemptHTTP2(true),
		WithMaxIdleConns(200),
		WithMaxIdleConnsPerHost(50),
	)

	if client.Timeout != 10*time.Second {
		t.Errorf("expected timeout to be 10s, got %v", client.Timeout)
	}

	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf(
			"expected transport to be *http.Transport, got %T",
			client.Transport,
		)
	}

	if !tr.DisableKeepAlives {
		t.Error("expected DisableKeepAlives to be true")
	}

	if !tr.ForceAttemptHTTP2 {
		t.Error("expected ForceAttemptHTTP2 to be true")
	}

	if tr.TLSClientConfig != tlsCfg {
		t.Error("expected TLSClientConfig to be set correctly")
	}

	if tr.TLSHandshakeTimeout != 17*time.Second {
		t.Errorf("expected TLSHandshakeTimeout to be 17s, got %v", tr.TLSHandshakeTimeout)
	}

	if tr.ExpectContinueTimeout != 18*time.Second {
		t.Errorf("expected ExpectContinueTimeout to be 18s, got %v", tr.ExpectContinueTimeout)
	}

	if tr.IdleConnTimeout != 19*time.Second {
		t.Errorf("expected IdleConnTimeout to be 19s, got %v", tr.IdleConnTimeout)
	}

	if tr.MaxIdleConns != 200 {
		t.Errorf("expected MaxIdleConns to be 200, got %d", tr.MaxIdleConns)
	}

	if tr.MaxIdleConnsPerHost != 50 {
		t.Errorf("expected MaxIdleConnsPerHost to be 50, got %d", tr.MaxIdleConnsPerHost)
	}
}

func TestNewClient_WithZeroTimeout(t *testing.T) {
	client := NewClient(WithTimeout(0))

	if client.Timeout != 0 {
		t.Errorf("expected timeout to be 0, got %v", client.Timeout)
	}
}

func TestNewClient_WithNegativeOptions(t *testing.T) {
	client := NewClient(
		WithTimeout(-10*time.Second),
		WithDialTimeout(-1*time.Second),
		WithKeepAlive(-1*time.Second),
		WithTLSHandshakeTimeout(-1*time.Second),
		WithExpectContinueTimeout(-1*time.Second),
		WithIdleConnTimeout(-1*time.Second),
		WithMaxIdleConns(-200),
		WithMaxIdleConnsPerHost(-50),
	)

	if client.Timeout != 5*time.Second {
		t.Errorf("expected timeout to be default 5s, got %v", client.Timeout)
	}

	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected transport to be *http.Transport, got %T", client.Transport)
	}

	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("expected TLSHandshakeTimeout to be default 10s, got %v", tr.TLSHandshakeTimeout)
	}

	if tr.ExpectContinueTimeout != 1*time.Second {
		t.Errorf("expected ExpectContinueTimeout to be default 1s, got %v", tr.ExpectContinueTimeout)
	}

	if tr.IdleConnTimeout != 90*time.Second {
		t.Errorf("expected IdleConnTimeout to be default 90s, got %v", tr.IdleConnTimeout)
	}

	if tr.MaxIdleConns != 100 {
		t.Errorf("expected MaxIdleConns to be default 100, got %d", tr.MaxIdleConns)
	}

	if tr.MaxIdleConnsPerHost != 100 {
		t.Errorf("expected MaxIdleConnsPerHost to be default 100, got %d", tr.MaxIdleConnsPerHost)
	}
}

func TestNewClient_WithHeadersAndRetry(t *testing.T) {
	client := NewClient(
		WithHeader(header.New("X-Test", "true")),
		WithRetry(retry.WithAttemptLimit(3)),
	)

	// The transport should be wrapped by retry, and then header.
	// Since we don't expose internal wrappers easily, we just ensure it's not
	// the base transport.
	if _, ok := client.Transport.(*http.Transport); ok {
		t.Error("expected transport to be wrapped by middlewares")
	}
}
