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

// Package cache provides a generic, auto-refreshing in-memory cache for a
// resource fetched from a URL.
//
// The core of the package is the [Controller], a [schedule.Tick] that
// periodically fetches a remote resource, parses it, and caches it in memory.
// It is designed to be resilient, with a built-in, configurable retry
// mechanism for handling transient network failures.
//
// The refresh interval is intelligently determined by the resource's caching
// headers (e.g., Cache-Control, Expires), but can be clamped within a
// specified min/max range. The controller also handles conditional requests
// using ETag and Last-Modified headers to reduce bandwidth and server load.
//
// # Usage
//
// A typical use case involves creating a [schedule.Scheduler], defining a
// [Mapper] function to parse the HTTP response, creating and configuring
// a [Controller], and then dispatching it to run in the background.
//
// Example:
//
//	type Resource struct {
//		// fields for the parsed data
//	}
//
//	// 1. Create a scheduler to manage the refresh ticks.
//	sched := schedule.New(context.Background())
//	defer sched.Shutdown()
//
//	// 2. Define a mapper to parse the response body into your target type.
//	var mapper cache.Mapper[Resource]
//	mapper = func(r *cache.Response) (Resource, error) {
//			var data Resource
//			err := json.Unmarshal(r.Body, &data)
//			return data, err
//		}
//
//		// 3. Create and configure the cache controller.
//		ctrl := cache.NewController(
//			http.DefaultClient,
//			"https://api.example.com/resource",
//			mapper,
//			cache.WithMinInterval(5*time.Minute),
//		)
//
//		// 4. Dispatch the controller to start fetching in the background.
//		sched.Dispatch(ctrl)
//
//		// 5. You can wait for the first successful fetch.
//		<-ctrl.Ready()
//
//		// 6. Get the cached data.
//		if data, ok := ctrl.Get(); ok {
//			fmt.Printf("Successfully fetched and cached data: %+v\n", data)
//		}
package cache

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/deep-rent/nexus/header"
	schedule "github.com/deep-rent/nexus/schedule"
)

const (
	// DefaultTimeout is the default timeout for a single HTTP request.
	DefaultTimeout = 30 * time.Second
	// DefaultMinInterval is the default lower bound for the refresh interval.
	DefaultMinInterval = 15 * time.Minute
	// DefaultMaxInterval is the default upper bound for the refresh interval.
	DefaultMaxInterval = 24 * time.Hour
)

// Mapper is a function that parses a response's raw response body into the
// target type T. It is responsible for decoding the data (e.g., from JSON or
// XML) and returning the structured result. An error should be returned if
// parsing fails fatally. For warnings or debug information, invoke the logger
// contained in the [Response]. If the mapping takes a considerable amount of
// time, it should generally respect the context contained in the [Response].
type Mapper[T any] func(r *Response) (T, error)

// Response provides contextual information to a [Mapper] function,
// including the response body, request context, and a logger.
type Response struct {
	// Body is the raw response payload to be mapped.
	Body []byte
	// Ctx is the context controlling the HTTP exchange.
	Ctx context.Context
	// Logger is the logger instance inherited from the [Controller].
	Logger *slog.Logger
}

// Controller manages the lifecycle of a cached resource. It implements
// [schedule.Tick], allowing it to be run by a scheduler to periodically
// refresh the resource from a URL.
type Controller[T any] interface {
	schedule.Tick
	// Get retrieves the currently cached resource. The boolean return value is
	// true if the cache has been successfully populated at least once.
	Get() (T, bool)
	// Ready returns a channel that is closed once the first successful fetch of
	// the resource is complete. This allows consumers to block until the cache
	// is warmed up.
	Ready() <-chan struct{}
}

// NewController creates and configures a new cache [Controller].
//
// It requires a URL for the resource to fetch and a [Mapper] function to parse
// the response.
func NewController[T any](
	client *http.Client,
	url string,
	mapper Mapper[T],
	opts ...Option,
) Controller[T] {
	cfg := config{
		minInterval: DefaultMinInterval,
		maxInterval: DefaultMaxInterval,
		logger:      slog.Default(),
	}
	for _, opt := range opts {
		opt(&cfg)
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

// controller is the internal implementation of the [Controller] interface.
type controller[T any] struct {
	// url is the endpoint from which the resource is fetched.
	url string
	// mapper is the user-provided function to parse the raw body.
	mapper Mapper[T]
	// client is the HTTP client used for fetching.
	client *http.Client
	// minInterval is the minimum wait time between refreshes.
	minInterval time.Duration
	// maxInterval is the maximum wait time between refreshes.
	maxInterval time.Duration
	// now is an internal hook for time mocking.
	now func() time.Time
	// logger handles internal logging of fetch cycles.
	logger *slog.Logger
	// readyOnce ensures the ready channel is closed only once.
	readyOnce sync.Once
	// readyChan is closed upon the first successful fetch.
	readyChan chan struct{}
	// mu protects the following cached fields.
	mu sync.RWMutex
	// resource stores the most recently successfully parsed T.
	resource T
	// ok indicates if resource has been populated.
	ok bool
	// etag stores the ETag from the last successful response.
	etag string
	// lastModified stores the Last-Modified header from the last response.
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

// Run executes a single fetch-and-cache cycle. It implements the
// [schedule.Tick] interface. It handles conditional requests, response
// parsing, and caching, and returns the duration to wait before the next run.
func (c *controller[T]) Run(ctx context.Context) time.Duration {
	c.logger.Debug("Fetching resource")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		// This is a non-retriable error in request creation.
		c.logger.Error("Failed to create request", slog.Any("error", err))
		return c.minInterval // Wait longer before trying to create it again.
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
		if !errors.Is(err, context.Canceled) {
			c.logger.Error(
				"HTTP request failed after retries",
				slog.Any("error", err),
			)
		}
		return c.minInterval
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			c.logger.Warn(
				"Failed to close response body",
				slog.Any("error", err),
			)
		}
	}()

	switch code := res.StatusCode; code {

	case http.StatusNotModified:
		c.logger.Debug("Resource unchanged", slog.String("etag", c.etag))
		c.ready()
		return c.delay(res.Header)

	case http.StatusOK:
		body, err := io.ReadAll(res.Body)
		if err != nil {
			c.logger.Error(
				"Failed to read response body",
				slog.Any("error", err),
			)
			return c.minInterval
		}
		resource, err := c.mapper(&Response{
			Body:   body,
			Ctx:    req.Context(),
			Logger: c.logger,
		})
		if err != nil {
			c.logger.Error(
				"Couldn't parse response body",
				slog.Any("error", err),
			)
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
		c.logger.Error(
			"Received a non-retriable HTTP status code",
			slog.Int("status", code),
		)
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
	// minInterval is the floor for refresh delays.
	minInterval time.Duration
	// maxInterval is the ceiling for refresh delays.
	maxInterval time.Duration
	// logger is the destination for internal logs.
	logger *slog.Logger
}

// Option is a function that configures the cache [Controller].
type Option func(*config)

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

// WithLogger provides a custom [slog.Logger] for the controller. If not
// provided, [slog.Default] is used.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}
