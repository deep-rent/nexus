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

package transport_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/deep-rent/nexus/net/header"
	"github.com/deep-rent/nexus/net/retry"
	"github.com/deep-rent/nexus/net/transport"
)

// base unwraps the response body limiter applied by [transport.New] and
// returns the underlying [http.Transport].
func base(t *testing.T, rt http.RoundTripper) *http.Transport {
	t.Helper()
	next, _, ok := transport.Unwrap(rt)
	if !ok {
		t.Fatalf("expected transport to be limited, got %T", rt)
	}
	tr, ok := next.(*http.Transport)
	if !ok {
		t.Fatalf("expected transport to be *http.Transport, got %T", next)
	}
	return tr
}

func TestNew_Defaults(t *testing.T) {
	rt := transport.New()

	tr := base(t, rt)

	if exp, act := false, tr.DisableKeepAlives; exp != act {
		t.Errorf("expected DisableKeepAlives to be %v, got %v", exp, act)
	}

	if exp, act := true, tr.ForceAttemptHTTP2; exp != act {
		t.Errorf("expected ForceAttemptHTTP2 to be %v, got %v", exp, act)
	}

	if tr.TLSClientConfig != nil {
		t.Error("expected TLSClientConfig to be nil by default")
	}

	if tr.Proxy == nil {
		t.Error("expected Proxy to be set by default")
	}

	if tr.DialContext == nil {
		t.Error("expected DialContext to be set by default")
	}

	if exp, act := 2*time.Second, tr.TLSHandshakeTimeout; exp != act {
		t.Errorf("expected TLSHandshakeTimeout to be %v, got %v", exp, act)
	}

	if exp, act := 1*time.Second, tr.ExpectContinueTimeout; exp != act {
		t.Errorf("expected ExpectContinueTimeout to be %v, got %v", exp, act)
	}

	if exp, act := 90*time.Second, tr.IdleConnTimeout; exp != act {
		t.Errorf("expected IdleConnTimeout to be %v, got %v", exp, act)
	}

	if exp, act := 1024, tr.MaxIdleConns; exp != act {
		t.Errorf("expected MaxIdleConns to be %v, got %v", exp, act)
	}

	if exp, act := 1024, tr.MaxIdleConnsPerHost; exp != act {
		t.Errorf("expected MaxIdleConnsPerHost to be %v, got %v", exp, act)
	}

	if exp, act := 1024, tr.MaxConnsPerHost; exp != act {
		t.Errorf("expected MaxConnsPerHost to be %v, got %v", exp, act)
	}

	if exp, act := time.Duration(0), tr.ResponseHeaderTimeout; exp != act {
		t.Errorf("expected ResponseHeaderTimeout to be %v, got %v", exp, act)
	}

	if exp, act := int64(64*1024), tr.MaxResponseHeaderBytes; exp != act {
		t.Errorf("expected MaxResponseHeaderBytes to be %v, got %v", exp, act)
	}

	if exp, act := 4*1024, tr.WriteBufferSize; exp != act {
		t.Errorf("expected WriteBufferSize to be %v, got %v", exp, act)
	}

	if exp, act := 4*1024, tr.ReadBufferSize; exp != act {
		t.Errorf("expected ReadBufferSize to be %v, got %v", exp, act)
	}
}

func TestNew_WithOptions(t *testing.T) {
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	http2Cfg := &http.HTTP2Config{}
	protocols := &http.Protocols{}
	proxy := func(*http.Request) (*url.URL, error) {
		return nil, nil
	}
	dialer := func(ctx context.Context, net, addr string) (net.Conn, error) {
		return nil, nil
	}

	rt := transport.New(
		transport.WithDialTimeout(15*time.Second),
		transport.WithKeepAlive(16*time.Second),
		transport.WithTLSHandshakeTimeout(17*time.Second),
		transport.WithExpectContinueTimeout(18*time.Second),
		transport.WithIdleConnTimeout(19*time.Second),
		transport.WithTLSConfig(tlsCfg),
		transport.WithDisableKeepAlives(true),
		transport.WithForceAttemptHTTP2(true),
		transport.WithMaxIdleConns(200),
		transport.WithMaxIdleConnsPerHost(50),
		transport.WithDisableCompression(true),
		transport.WithMaxConnsPerHost(60),
		transport.WithResponseHeaderTimeout(20*time.Second),
		transport.WithMaxResponseHeaderBytes(1024),
		transport.WithWriteBufferSize(2048),
		transport.WithReadBufferSize(4096),
		transport.WithHTTP2Config(http2Cfg),
		transport.WithProtocols(protocols),
		transport.WithProxy(proxy),
		transport.WithDialContext(dialer),
	)

	tr := base(t, rt)

	if !tr.DisableKeepAlives {
		t.Error("expected DisableKeepAlives to be true")
	}

	if !tr.ForceAttemptHTTP2 {
		t.Error("expected ForceAttemptHTTP2 to be true")
	}

	if tr.TLSClientConfig == tlsCfg {
		t.Error("expected TLSClientConfig to be cloned")
	}
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected cloned TLSClientConfig to retain values")
	}

	if tr.Proxy == nil {
		t.Error("expected Proxy to be set")
	}

	if tr.DialContext == nil {
		t.Error("expected DialContext to be set")
	}

	if exp, act := 17*time.Second, tr.TLSHandshakeTimeout; exp != act {
		t.Errorf("expected TLSHandshakeTimeout to be %v, got %v", exp, act)
	}

	if exp, act := 18*time.Second, tr.ExpectContinueTimeout; exp != act {
		t.Errorf("expected ExpectContinueTimeout to be %v, got %v", exp, act)
	}

	if exp, act := 19*time.Second, tr.IdleConnTimeout; exp != act {
		t.Errorf("expected IdleConnTimeout to be %v, got %v", exp, act)
	}

	if exp, act := 200, tr.MaxIdleConns; exp != act {
		t.Errorf("expected MaxIdleConns to be %v, got %v", exp, act)
	}

	if exp, act := 50, tr.MaxIdleConnsPerHost; exp != act {
		t.Errorf("expected MaxIdleConnsPerHost to be %v, got %v", exp, act)
	}

	if !tr.DisableCompression {
		t.Error("expected DisableCompression to be true")
	}

	if exp, act := 60, tr.MaxConnsPerHost; exp != act {
		t.Errorf("expected MaxConnsPerHost to be %v, got %v", exp, act)
	}

	if exp, act := 20*time.Second, tr.ResponseHeaderTimeout; exp != act {
		t.Errorf("expected ResponseHeaderTimeout to be %v, got %v", exp, act)
	}

	if exp, act := int64(1024), tr.MaxResponseHeaderBytes; exp != act {
		t.Errorf("expected MaxResponseHeaderBytes to be %v, got %v", exp, act)
	}

	if exp, act := 2048, tr.WriteBufferSize; exp != act {
		t.Errorf("expected WriteBufferSize to be %v, got %v", exp, act)
	}

	if exp, act := 4096, tr.ReadBufferSize; exp != act {
		t.Errorf("expected ReadBufferSize to be %v, got %v", exp, act)
	}

	if tr.HTTP2 != http2Cfg {
		t.Error("expected HTTP2 config to be set correctly")
	}

	if tr.Protocols != protocols {
		t.Error("expected Protocols to be set correctly")
	}
}

func TestNew_WithNegativeOptions(t *testing.T) {
	rt := transport.New(
		transport.WithDialTimeout(-1*time.Second),
		transport.WithKeepAlive(-1*time.Second),
		transport.WithTLSHandshakeTimeout(-1*time.Second),
		transport.WithExpectContinueTimeout(-1*time.Second),
		transport.WithIdleConnTimeout(-1*time.Second),
		transport.WithMaxIdleConns(-200),
		transport.WithMaxIdleConnsPerHost(-50),
		transport.WithMaxConnsPerHost(-60),
		transport.WithResponseHeaderTimeout(-20*time.Second),
		transport.WithMaxResponseHeaderBytes(-1024),
		transport.WithWriteBufferSize(-2048),
		transport.WithReadBufferSize(-4096),
	)

	tr := base(t, rt)

	if exp, act := 2*time.Second, tr.TLSHandshakeTimeout; exp != act {
		t.Errorf("expected TLSHandshakeTimeout to be %v, got %v", exp, act)
	}

	if exp, act := 1*time.Second, tr.ExpectContinueTimeout; exp != act {
		t.Errorf("expected ExpectContinueTimeout to be %v, got %v", exp, act)
	}

	if exp, act := 90*time.Second, tr.IdleConnTimeout; exp != act {
		t.Errorf("expected IdleConnTimeout to be %v, got %v", exp, act)
	}

	if exp, act := 1024, tr.MaxIdleConns; exp != act {
		t.Errorf("expected MaxIdleConns to be %v, got %v", exp, act)
	}

	if exp, act := 1024, tr.MaxIdleConnsPerHost; exp != act {
		t.Errorf("expected MaxIdleConnsPerHost to be %v, got %v", exp, act)
	}
}

func TestNew_WithHeadersAndRetry(t *testing.T) {
	rt := transport.New(
		transport.WithHeader(header.New("X-Test", "true")),
		transport.WithRetry(retry.WithAttemptLimit(3)),
		transport.WithUserAgent("my-agent/1.0"),
	)

	if _, ok := rt.(*http.Transport); ok {
		t.Error("expected transport to be wrapped by middlewares")
	}
}

func TestNewClient_Timeout(t *testing.T) {
	clientA := transport.NewClient(10 * time.Second) // Positive
	if exp, act := 10*time.Second, clientA.Timeout; exp != act {
		t.Errorf("expected timeout to be %v, got %v", exp, act)
	}
	clientB := transport.NewClient(0) // Zero
	if exp, act := 5*time.Second, clientB.Timeout; exp != act {
		t.Errorf("expected timeout to be %v, got %v", exp, act)
	}
	clientC := transport.NewClient(-1 * time.Second) // Negative
	if exp, act := 5*time.Second, clientC.Timeout; exp != act {
		t.Errorf("expected timeout to be %v, got %v", exp, act)
	}
}
