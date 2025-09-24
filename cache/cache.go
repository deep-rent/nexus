package cache

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deep-rent/nexus/backoff"
	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/scheduler"
)

const (
	DefaultTimeout     = 30 * time.Second
	DefaultMinInterval = 30 * time.Minute
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
		clock:       time.Now,
		backoff:     backoff.New(),
		log:         slog.Default(),
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
		t := &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           d.DialContext,
			TLSClientConfig:       c.tls,
			TLSHandshakeTimeout:   c.timeout / 3,
			ResponseHeaderTimeout: c.timeout * 9 / 10,
			ExpectContinueTimeout: 1 * time.Second,
			DisableKeepAlives:     true,
		}
		client = &http.Client{
			Timeout:   c.timeout,
			Transport: header.NewTransport(t, c.headers),
		}
	}

	return &controller[T]{
		url:    url,
		mapper: mapper,
		client: client,
		lifetime: &Lifetime{
			minInterval: c.minInterval,
			maxInterval: c.maxInterval,
			clock:       c.clock,
		},
		backoff:   c.backoff,
		log:       c.log,
		readyChan: make(chan struct{}),
	}
}

type controller[T any] struct {
	url       string
	mapper    Mapper[T]
	client    *http.Client
	lifetime  *Lifetime
	backoff   backoff.Strategy
	log       *slog.Logger
	readyOnce sync.Once
	readyChan chan struct{}

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
	c.log.Debug("Fetching resource")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		c.log.Error("Failed to create request", "error", err)
		return c.backoff.Next()
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
			c.log.Warn("HTTP request failed", "error", err)
		}
		return c.backoff.Next()
	}
	defer res.Body.Close()

	switch res.StatusCode {

	case http.StatusNotModified:
		c.log.Debug("ETag match, resource unchanged", "etag", c.etag)
		c.backoff.Done()
		c.ready()
		return c.lifetime.Get(res.Header)

	case http.StatusOK:
		body, err := io.ReadAll(res.Body)
		if err != nil {
			c.log.Error("Failed to read response body", "error", err)
			return c.backoff.Next()
		}

		resource, err := c.mapper(body)
		if err != nil {
			c.log.Error("Couldn't parse response body", "error", err)
			return c.backoff.Next()
		}

		c.mu.Lock()
		c.resource = resource
		c.etag = res.Header.Get(header.ETag)
		c.lastModified = res.Header.Get(header.LastModified)
		c.ok = true
		c.mu.Unlock()

		c.backoff.Done()
		c.log.Info("Resource updated successfully")
		c.ready()
		return c.lifetime.Get(res.Header)

	default:
		c.log.Warn("Unsuccessful HTTP status", "code", res.StatusCode)
		return c.backoff.Next()
	}
}

type Lifetime struct {
	minInterval time.Duration
	maxInterval time.Duration
	clock       func() time.Time
}

func (l *Lifetime) Get(h http.Header) time.Duration {
	if v := h.Get(header.CacheControl); v != "" {
		for directive := range strings.SplitSeq(v, ",") {
			directive = strings.TrimSpace(directive)
			if s, ok := strings.CutPrefix(directive, "max-age="); ok {
				if exp, err := strconv.Atoi(s); err == nil && exp > 0 {
					ttl := time.Duration(exp) * time.Second
					return min(max(ttl, l.minInterval), l.maxInterval)
				}
			}
		}
	}
	if v := h.Get(header.Expires); v != "" {
		if exp, err := http.ParseTime(v); err == nil {
			if ttl := exp.Sub(l.clock()); ttl > 0 {
				return min(max(ttl, l.minInterval), l.maxInterval)
			}
		}
	}
	return l.minInterval
}

var _ Controller[any] = (*controller[any])(nil)

type config struct {
	client      *http.Client
	timeout     time.Duration
	headers     map[string]string
	tls         *tls.Config
	minInterval time.Duration
	maxInterval time.Duration
	clock       func() time.Time
	backoff     backoff.Strategy
	log         *slog.Logger
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

func WithClock(fn func() time.Time) Option {
	return func(c *config) {
		if fn != nil {
			c.clock = fn
		}
	}
}

func WithBackoff(s backoff.Strategy) Option {
	return func(c *config) {
		if s != nil {
			c.backoff = s
		}
	}
}

func WithLogger(log *slog.Logger) Option {
	return func(c *config) {
		if log != nil {
			c.log = log
		}
	}
}
