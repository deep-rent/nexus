package transport

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/retry"
)

func TestNew_Defaults(t *testing.T) {
	rt := New()

	tr, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("expected transport to be *http.Transport, got %T", rt)
	}

	if tr.DisableKeepAlives {
		t.Error("expected DisableKeepAlives to be false by default")
	}

	if !tr.ForceAttemptHTTP2 {
		t.Error("expected ForceAttemptHTTP2 to be true by default")
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
		t.Errorf(
			"expected MaxIdleConnsPerHost to be default %v, got %v",
			exp,
			act,
		)
	}

	if exp, act := 1024, tr.MaxConnsPerHost; exp != act {
		t.Errorf("expected MaxConnsPerHost to be default %v, got %v", exp, act)
	}

	if exp, act := time.Duration(0), tr.ResponseHeaderTimeout; exp != act {
		t.Errorf(
			"expected ResponseHeaderTimeout to be default %v, got %v",
			exp,
			act,
		)
	}

	if exp, act := int64(64*1024), tr.MaxResponseHeaderBytes; exp != act {
		t.Errorf(
			"expected MaxResponseHeaderBytes to be default %v, got %v",
			exp,
			act,
		)
	}

	if exp, act := 4*1024, tr.WriteBufferSize; exp != act {
		t.Errorf("expected WriteBufferSize to be default %v, got %v", exp, act)
	}

	if exp, act := 4*1024, tr.ReadBufferSize; exp != act {
		t.Errorf("expected ReadBufferSize to be default %v, got %v", exp, act)
	}
}

func TestNew_WithOptions(t *testing.T) {
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	http2Cfg := &http.HTTP2Config{}
	protocols := &http.Protocols{}
	proxyFunc := func(*http.Request) (*url.URL, error) { return nil, nil }
	dialerFunc := func(ctx context.Context, network, addr string) (net.Conn, error) { return nil, nil }

	rt := New(
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
		WithDisableCompression(true),
		WithMaxConnsPerHost(60),
		WithResponseHeaderTimeout(20*time.Second),
		WithMaxResponseHeaderBytes(1024),
		WithWriteBufferSize(2048),
		WithReadBufferSize(4096),
		WithHTTP2Config(http2Cfg),
		WithProtocols(protocols),
		WithProxy(proxyFunc),
		WithDialContext(dialerFunc),
	)

	tr, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("expected transport to be *http.Transport, got %T", rt)
	}

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
	rt := New(
		WithDialTimeout(-1*time.Second),
		WithKeepAlive(-1*time.Second),
		WithTLSHandshakeTimeout(-1*time.Second),
		WithExpectContinueTimeout(-1*time.Second),
		WithIdleConnTimeout(-1*time.Second),
		WithMaxIdleConns(-200),
		WithMaxIdleConnsPerHost(-50),
		WithMaxConnsPerHost(-60),
		WithResponseHeaderTimeout(-20*time.Second),
		WithMaxResponseHeaderBytes(-1024),
		WithWriteBufferSize(-2048),
		WithReadBufferSize(-4096),
	)

	tr, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("expected transport to be *http.Transport, got %T", rt)
	}

	if exp, act := 2*time.Second, tr.TLSHandshakeTimeout; exp != act {
		t.Errorf(
			"expected TLSHandshakeTimeout to be default %v, got %v",
			exp,
			act,
		)
	}

	if exp, act := 1*time.Second, tr.ExpectContinueTimeout; exp != act {
		t.Errorf(
			"expected ExpectContinueTimeout to be default %v, got %v",
			exp,
			act,
		)
	}

	if exp, act := 90*time.Second, tr.IdleConnTimeout; exp != act {
		t.Errorf("expected IdleConnTimeout to be default %v, got %v", exp, act)
	}

	if exp, act := 1024, tr.MaxIdleConns; exp != act {
		t.Errorf("expected MaxIdleConns to be default %v, got %v", exp, act)
	}

	if exp, act := 1024, tr.MaxIdleConnsPerHost; exp != act {
		t.Errorf(
			"expected MaxIdleConnsPerHost to be default %v, got %v",
			exp,
			act,
		)
	}
}

func TestNew_WithHeadersAndRetry(t *testing.T) {
	rt := New(
		WithHeader(header.New("X-Test", "true")),
		WithRetry(retry.WithAttemptLimit(3)),
		WithUserAgent("my-agent/1.0"),
	)

	if _, ok := rt.(*http.Transport); ok {
		t.Error("expected transport to be wrapped by middlewares")
	}
}

func TestNewClient_Timeout(t *testing.T) {
	client := NewClient(10 * time.Second)
	if exp, act := 10*time.Second, client.Timeout; exp != act {
		t.Errorf("expected timeout to be %v, got %v", exp, act)
	}

	// Test default fallback for zero timeout
	clientZero := NewClient(0)
	if exp, act := 5*time.Second, clientZero.Timeout; exp != act {
		t.Errorf("expected timeout to be %v, got %v", exp, act)
	}

	// Test default fallback for negative timeout
	clientNegative := NewClient(-1 * time.Second)
	if exp, act := 5*time.Second, clientNegative.Timeout; exp != act {
		t.Errorf("expected timeout to be %v, got %v", exp, act)
	}
}
