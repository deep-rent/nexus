package transport

import (
	"crypto/tls"
	"net/http"
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

func TestNew_WithOptions(t *testing.T) {
	tlsCfg := &tls.Config{InsecureSkipVerify: true}

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

	if tr.TLSClientConfig != tlsCfg {
		t.Error("expected TLSClientConfig to be set correctly")
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
