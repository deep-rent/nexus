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
	client := NewClient(Options{})

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
}

func TestNewClient_WithOptions(t *testing.T) {
	tlsCfg := &tls.Config{InsecureSkipVerify: true}

	client := NewClient(Options{
		Timeout:           10 * time.Second,
		TLSConfig:         tlsCfg,
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
	})

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
}

func TestNewClient_WithHeadersAndRetry(t *testing.T) {
	client := NewClient(Options{
		Headers: []header.Header{header.New("X-Test", "true")},
		Retry:   []retry.Option{retry.WithAttemptLimit(3)},
	})

	// The transport should be wrapped by retry, and then header.
	// Since we don't expose internal wrappers easily, we just ensure it's not
	// the base transport.
	if _, ok := client.Transport.(*http.Transport); ok {
		t.Error("expected transport to be wrapped by middlewares")
	}
}
