package cache

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/deep-rent/nexus/backoff"
	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/retry"
	"github.com/deep-rent/nexus/scheduler"
)

const (
	DefaultTimeout     = 30 * time.Second
	DefaultMinInterval = 15 * time.Minute
	DefaultMaxInterval = 24 * time.Hour
)

type Mapper[T any] func(body []byte) (T, error)

type Controller[T any] interface {
	scheduler.Tick

	Get() (T, bool)
	Ready() <-chan struct{}
}

func NewController[T any](
	url string,
	mapper Mapper[T],
	opts ...Option,
) Controller[T] {
	c := config{
		client:      nil,
		timeout:     DefaultTimeout,
		headers:     make(map[string]string),
		minInterval: DefaultMinInterval,
		maxInterval: DefaultMaxInterval,
		logger:      slog.Default(),
	}
	for _, opt := range opts {
		opt(&c)
	}

	client := c.client
	if client == nil {
		d := &net.Dialer{
			Timeout:   c.timeout / 3,
			KeepAlive: 0,
		}
		var t http.RoundTripper = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           d.DialContext,
			TLSClientConfig:       c.tls,
			TLSHandshakeTimeout:   c.timeout / 3,
			ResponseHeaderTimeout: c.timeout * 9 / 10,
			ExpectContinueTimeout: 1 * time.Second,
			DisableKeepAlives:     true,
		}
		t = retry.NewTransport(header.NewTransport(t, c.headers), c.retry...)
		client = &http.Client{
			Timeout:   c.timeout,
			Transport: t,
		}
	}

	return &controller[T]{
		url:         url,
		mapper:      mapper,
		client:      client,
		minInterval: c.minInterval,
		maxInterval: c.maxInterval,
		logger:      c.logger,
		readyChan:   make(chan struct{}),
	}
}

type controller[T any] struct {
	url         string
	mapper      Mapper[T]
	client      *http.Client
	minInterval time.Duration
	maxInterval time.Duration
	now         func() time.Time
	backoff     backoff.Strategy
	logger      *slog.Logger
	readyOnce   sync.Once
	readyChan   chan struct{}

	mu           sync.RWMutex
	resource     T
	ok           bool
	etag         string
	lastModified string
}

func (c *controller[T]) Get() (T, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.resource, c.ok
}

func (c *controller[T]) Ready() <-chan struct{} {
	return c.readyChan
}

func (c *controller[T]) ready() {
	c.readyOnce.Do(func() { close(c.readyChan) })
}

func (c *controller[T]) Run(ctx context.Context) time.Duration {
	c.logger.Debug("Fetching resource")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		// This is a non-retriable error in request creation.
		c.logger.Error("Failed to create request", "error", err)
		return c.minInterval // Wait a long time before trying to create it again.
	}

	c.mu.RLock()
	if c.etag != "" {
		req.Header.Set(header.IfNoneMatch, c.etag)
	}
	if c.lastModified != "" {
		req.Header.Set(header.IfModifiedSince, c.lastModified)
	}
	c.mu.RUnlock()

	res, err := c.client.Do(req)
	if err != nil {
		if err != context.Canceled {
			c.logger.Error("HTTP request failed after retries", "error", err)
		}
		return c.minInterval
	}
	defer res.Body.Close()

	switch code := res.StatusCode; code {

	case http.StatusNotModified:
		c.logger.Debug("Resource unchanged", "etag", c.etag)
		c.ready()
		return c.delay(res.Header)

	case http.StatusOK:
		body, err := io.ReadAll(res.Body)
		if err != nil {
			c.logger.Error("Failed to read response body", "error", err)
			return c.minInterval
		}
		resource, err := c.mapper(body)
		if err != nil {
			c.logger.Error("Couldn't parse response body", "error", err)
			return c.minInterval
		}
		c.mu.Lock()
		c.resource = resource
		c.etag = res.Header.Get(header.ETag)
		c.lastModified = res.Header.Get(header.LastModified)
		c.ok = true
		c.mu.Unlock()

		c.logger.Info("Resource updated successfully")
		c.ready()
		return c.delay(res.Header)

	default:
		c.logger.Error("Received a non-retriable HTTP status code", "status", code)
		return c.minInterval
	}
}

func (c *controller[T]) delay(h http.Header) time.Duration {
	d := header.Lifetime(h, c.now)
	if d > c.maxInterval {
		return c.maxInterval
	}
	if d < c.minInterval {
		return c.minInterval
	}
	return d
}

var _ Controller[any] = (*controller[any])(nil)

type config struct {
	client      *http.Client
	timeout     time.Duration
	headers     map[string]string
	tls         *tls.Config
	minInterval time.Duration
	maxInterval time.Duration
	retry       []retry.Option
	logger      *slog.Logger
}

type Option func(*config)

func WithClient(client *http.Client) Option {
	return func(c *config) {
		if client != nil {
			c.client = client
		}
	}
}

func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.timeout = d
		}
	}
}

func WithHeader(k, v string) Option {
	return func(c *config) {
		c.headers[k] = v
	}
}

func WithTLSConfig(tls *tls.Config) Option {
	return func(c *config) {
		c.tls = tls
	}
}

func WithMinInterval(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.minInterval = d
		}
	}
}

func WithMaxInterval(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.maxInterval = d
		}
	}
}

func WithRetryOptions(opts ...retry.Option) Option {
	return func(c *config) {
		c.retry = append(c.retry, opts...)
	}
}

func WithLogger(log *slog.Logger) Option {
	return func(c *config) {
		if log != nil {
			c.logger = log
		}
	}
}
