// Package cache provides a generic, auto-refreshing in-memory cache for a
// resource fetched from a URL.
//
// The core of the package is the Controller, a scheduler.Tick that periodically
// fetches a remote resource, parses it, and caches it in memory. It is designed
// to be resilient, with a built-in, configurable retry mechanism for handling
// transient network failures.
//
// The refresh interval is intelligently determined by the resource's caching
// headers (e.g., Cache-Control, Expires), but can be clamped within a specified
// min/max range. The controller also handles conditional requests using ETag
// and Last-Modified headers to reduce bandwidth and server load.
//
// # Usage
//
// A typical use case involves creating a scheduler, defining a Mapper function
// to parse the HTTP response, creating and configuring a Controller, and then
// dispatching it to run in the background.
//
//	type Resource struct {
//		// fields for the parsed data
//	}
//
//	// 1. Create a scheduler to manage the refresh ticks.
//	s := scheduler.New(context.Background())
//	defer s.Shutdown()
//
//	// 2. Define a mapper to parse the response body into your target type.
//	var mapper cache.Mapper[Resource] = func(body []byte) (Resource, error) {
//		var data Resource
//		err := json.Unmarshal(body, &data)
//		return data, err
//	}
//
//	// 3. Create and configure the cache controller.
//	ctrl := cache.NewController(
//		"https://api.example.com/resource",
//		mapper,
//		cache.WithMinInterval(5*time.Minute),
//		cache.WithHeader("Authorization", "Bearer *****"),
//	)
//
//	// 4. Dispatch the controller to start fetching in the background.
//	s.Dispatch(ctrl)
//
//	// 5. You can wait for the first successful fetch.
//	<-ctrl.Ready()
//
//	// 6. Get the cached data.
//	if data, ok := ctrl.Get(); ok {
//		fmt.Printf("Successfully fetched and cached data: %+v\n", data)
//	}
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

// Default configuration values for the cache controller.
const (
	// DefaultTimeout is the default timeout for a single HTTP request.
	DefaultTimeout = 30 * time.Second
	// DefaultMinInterval is the default lower bound for the refresh interval.
	DefaultMinInterval = 15 * time.Minute
	// DefaultMaxInterval is the default upper bound for the refresh interval.
	DefaultMaxInterval = 24 * time.Hour
)

// Mapper is a function that parses a raw response body into the target type T.
// It is responsible for decoding the data (e.g., from JSON or XML) and
// returning the structured result.
// An error should be returned if parsing fails.
type Mapper[T any] func(body []byte) (T, error)

// Controller manages the lifecycle of a cached resource. It implements
// scheduler.Tick, allowing it to be run by a scheduler to periodically refresh
// the resource from a URL.
type Controller[T any] interface {
	scheduler.Tick
	// Get retrieves the currently cached resource. The boolean return value is
	// true if the cache has been successfully populated at least once.
	Get() (T, bool)
	// Ready returns a channel that is closed once the first successful fetch of
	// the resource is complete. This allows consumers to block until the cache
	// is warmed up.
	Ready() <-chan struct{}
}

// NewController creates and configures a new cache Controller.
//
// It requires a URL for the resource to fetch and a Mapper function to parse
// the response. If no http.Client is provided via options, it creates a default
// one with a sensible timeout and a retry transport.
func NewController[T any](
	url string,
	mapper Mapper[T],
	opts ...Option,
) Controller[T] {
	cfg := config{
		client:      nil,
		timeout:     DefaultTimeout,
		headers:     make([]header.Header, 0, 3),
		minInterval: DefaultMinInterval,
		maxInterval: DefaultMaxInterval,
		logger:      slog.Default(),
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	client := cfg.client
	if client == nil {
		d := &net.Dialer{
			Timeout:   cfg.timeout / 3,
			KeepAlive: 0,
		}
		var t http.RoundTripper = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           d.DialContext,
			TLSClientConfig:       cfg.tls,
			TLSHandshakeTimeout:   cfg.timeout / 3,
			ResponseHeaderTimeout: cfg.timeout * 9 / 10,
			ExpectContinueTimeout: 1 * time.Second,
			DisableKeepAlives:     true,
		}
		t = retry.NewTransport(header.NewTransport(t, cfg.headers...), cfg.retry...)
		client = &http.Client{
			Timeout:   cfg.timeout,
			Transport: t,
		}
	}

	return &controller[T]{
		url:         url,
		mapper:      mapper,
		client:      client,
		minInterval: cfg.minInterval,
		maxInterval: cfg.maxInterval,
		logger:      cfg.logger,
		readyChan:   make(chan struct{}),
	}
}

// controller is the internal implementation of the Controller interface.
type controller[T any] struct {
	url          string
	mapper       Mapper[T]
	client       *http.Client
	minInterval  time.Duration
	maxInterval  time.Duration
	now          func() time.Time
	backoff      backoff.Strategy
	logger       *slog.Logger
	readyOnce    sync.Once
	readyChan    chan struct{}
	mu           sync.RWMutex
	resource     T
	ok           bool
	etag         string
	lastModified string
}

// Get retrieves the currently cached resource.
func (c *controller[T]) Get() (T, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.resource, c.ok
}

// Ready returns a channel that is closed when the cache is first populated.
func (c *controller[T]) Ready() <-chan struct{} {
	return c.readyChan
}

// ready ensures the ready channel is closed exactly once.
func (c *controller[T]) ready() {
	c.readyOnce.Do(func() { close(c.readyChan) })
}

// Run executes a single fetch-and-cache cycle. It implements the scheduler.Tick
// interface. It handles conditional requests, response parsing, and caching,
// and returns the duration to wait before the next run.
func (c *controller[T]) Run(ctx context.Context) time.Duration {
	c.logger.Debug("Fetching resource")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		// This is a non-retriable error in request creation.
		c.logger.Error("Failed to create request", "error", err)
		return c.minInterval // Wait a long time before trying to create it again.
	}

	// Add conditional headers if we have them from a previous request.
	c.mu.RLock()
	if c.etag != "" {
		req.Header.Set("If-None-Match", c.etag)
	}
	if c.lastModified != "" {
		req.Header.Set("If-Modified-Since", c.lastModified)
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
		c.etag = res.Header.Get("ETag")
		c.lastModified = res.Header.Get("Last-Modified")
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

// delay calculates the duration until the next fetch based on caching headers,
// clamped by the configured min/max intervals.
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

// config holds the internal configuration for the cache controller.
type config struct {
	client      *http.Client
	timeout     time.Duration
	headers     []header.Header
	tls         *tls.Config
	minInterval time.Duration
	maxInterval time.Duration
	retry       []retry.Option
	logger      *slog.Logger
}

// Option is a function that configures the cache Controller.
type Option func(*config)

// WithClient provides a custom http.Client to be used for requests. This is
// useful for advanced configurations, such as custom transports or connection
// pooling. If not provided, a default client with retry logic is created.
func WithClient(client *http.Client) Option {
	return func(c *config) {
		if client != nil {
			c.client = client
		}
	}
}

// WithTimeout sets the total timeout for a single HTTP fetch attempt, including
// connection, redirects, and reading the response body. This is ignored if a
// custom client is provided via WithClient.
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithHeader adds a static header to every request sent by the controller. This
// can be called multiple times to add multiple headers.
func WithHeader(k, v string) Option {
	return func(c *config) {
		c.headers = append(c.headers, header.New(k, v))
	}
}

// WithTLSConfig provides a custom tls.Config for the default HTTP transport.
// This is ignored if a custom client is provided via WithClient.
func WithTLSConfig(tls *tls.Config) Option {
	return func(c *config) {
		c.tls = tls
	}
}

// WithMinInterval sets the minimum duration between refresh attempts. The
// refresh delay, typically determined by caching headers, will not be shorter
// than this.
func WithMinInterval(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.minInterval = d
		}
	}
}

// WithMaxInterval sets the maximum duration between refresh attempts. The
// refresh delay will not be longer than this value.
func WithMaxInterval(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.maxInterval = d
		}
	}
}

// WithRetryOptions configures the retry mechanism for the default HTTP client.
// These options are ignored if a custom client is provided via WithClient.
func WithRetryOptions(opts ...retry.Option) Option {
	return func(c *config) {
		c.retry = append(c.retry, opts...)
	}
}

// WithLogger provides a custom slog.Logger for the controller. If not provided,
// slog.Default() is used.
func WithLogger(log *slog.Logger) Option {
	return func(c *config) {
		if log != nil {
			c.logger = log
		}
	}
}
