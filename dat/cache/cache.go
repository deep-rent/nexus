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

package cache

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/deep-rent/nexus/net/header"
	"github.com/deep-rent/nexus/net/transport"
	"github.com/deep-rent/nexus/std/backoff"
	"github.com/deep-rent/nexus/std/clock"
	"github.com/deep-rent/nexus/std/jitter"
	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/sys/metrics"
	"github.com/deep-rent/nexus/sys/schedule"
)

// Mapper is a function that parses a response's raw response body into the
// target type T. It is responsible for decoding the data (e.g., from JSON or
// XML) and returning the structured result. An error should be returned if
// parsing fails fatally, which leaves the previously cached value in place and
// schedules a retry. For warnings or debug information, invoke the logger
// contained in the [Response]. If the mapping takes a considerable amount of
// time, it should generally respect the context contained in the [Response].
type Mapper[T any] func(r *Response) (T, error)

// Response provides contextual information to a [Mapper] function, including
// the response body, request context, and a logger.
type Response struct {
	// Body is the raw response payload to be mapped.
	Body []byte
	// Ctx is the context controlling the HTTP exchange.
	Ctx context.Context
	// Logger is the logger instance inherited from the [Controller].
	Logger *log.Logger
}

// Controller manages the lifecycle of a cached resource. It implements
// [schedule.Tick], allowing it to be run by a scheduler to periodically
// refresh the resource from a URL.
type Controller[T any] interface {
	schedule.Tick

	// Get retrieves the currently cached resource. The boolean return value is
	// true if the cache has been successfully populated at least once. Once
	// populated, the cache retains the last known good value even if later
	// refreshes fail.
	Get() (T, bool)

	// Ready returns a channel that is closed once the resource has been
	// fetched and mapped successfully for the first time. This allows
	// consumers to block until the cache is warmed up. When the channel is
	// closed, [Controller.Get] is guaranteed to report a value.
	Ready() <-chan struct{}
}

// NewController creates and configures a new cache [Controller].
//
// It requires a URL for the resource to fetch and a [Mapper] function to parse
// the response. Fetching uses [transport.DefaultClient] unless [WithClient]
// overrides it.
//
// It panics if url is empty or mapper is nil. A syntactically invalid URL is
// not rejected here; it surfaces as a logged error on the first refresh.
func NewController[T any](
	url string,
	mapper Mapper[T],
	opts ...Option,
) Controller[T] {
	if url == "" {
		panic("URL must not be empty")
	}
	if mapper == nil {
		panic("mapper is required")
	}

	cfg := config{
		minInterval: DefaultMinInterval,
		maxInterval: DefaultMaxInterval,
		logger:      log.Discard(),
		client:      transport.DefaultClient,
		now:         clock.System,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	// A ceiling below the floor would make the clamp order-dependent.
	cfg.maxInterval = max(cfg.maxInterval, cfg.minInterval)

	if cfg.registry == nil {
		cfg.registry = metrics.DefaultRegistry
	}

	if cfg.backoff == nil {
		// Retries escalate up to the regular refresh interval, so a resource
		// that stays broken is not polled more often than a healthy one.
		cfg.backoff = backoff.New(
			backoff.WithMinDelay(min(DefaultRetryDelay, cfg.minInterval)),
			backoff.WithMaxDelay(cfg.minInterval),
		)
	}

	return &controller[T]{
		url:         url,
		mapper:      mapper,
		client:      cfg.client,
		minInterval: cfg.minInterval,
		maxInterval: cfg.maxInterval,
		backoff:     cfg.backoff,
		jitter:      jitter.New(cfg.jitter, nil),
		logger:      cfg.logger,
		now:         cfg.now,
		stats:       newStats(cfg.registry, url),
		readyChan:   make(chan struct{}),
	}
}

// controller is the internal implementation of the [Controller] interface.
type controller[T any] struct {
	url         string           // endpoint from which the resource is fetched
	mapper      Mapper[T]        // parses the raw body into T
	client      *http.Client     // HTTP client used for fetching
	minInterval time.Duration    // minimum wait between successful refreshes
	maxInterval time.Duration    // maximum wait between refreshes
	backoff     backoff.Strategy // delays between failed refreshes
	jitter      *jitter.Jitter   // scatters the refresh interval
	logger      *log.Logger      // destination for internal logs
	now         clock.Clock      // clock used to interpret date headers
	stats       stats            // counts refresh cycles by outcome

	readyOnce sync.Once     // ensures the ready channel is closed only once
	readyChan chan struct{} // closed upon the first successful fetch

	mu           sync.RWMutex // guards the fields below
	resource     T            // most recently parsed resource
	ok           bool         // whether resource has been populated
	failures     int          // consecutive failed refreshes
	etag         string       // ETag of the last successful response
	lastModified string       // Last-Modified of the last successful response
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
	c.logger.Debug(ctx, "Fetching resource")

	res, err := c.fetch(ctx)
	if err != nil {
		// A canceled context means the scheduler is shutting down, which is
		// not a failure of the resource.
		if !errors.Is(err, context.Canceled) {
			c.logger.Error(ctx,
				"Failed to fetch resource",
				log.Error(err),
			)
		}
		return c.retry(ctx)
	}
	defer c.close(res)

	switch code := res.StatusCode; code {
	case http.StatusNotModified:
		return c.unchanged(ctx, res)

	case http.StatusOK:
		return c.update(ctx, res)

	default:
		c.logger.Error(ctx,
			"Received an unexpected HTTP status code",
			log.Int("status", code),
		)
		return c.retry(ctx)
	}
}

// fetch issues a conditional GET for the resource.
func (c *controller[T]) fetch(ctx context.Context) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}

	// Add conditional headers if we have them from a previous response.
	c.mu.RLock()
	etag, lastModified := c.etag, c.lastModified
	c.mu.RUnlock()

	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}

	return c.client.Do(req)
}

// unchanged handles a 304 response, retaining the currently cached value.
func (c *controller[T]) unchanged(
	ctx context.Context,
	res *http.Response,
) time.Duration {
	c.mu.RLock()
	etag, ok := c.etag, c.ok
	c.mu.RUnlock()

	// A 304 without a cached value means our validators are out of step with
	// the server, so they are dropped to force an unconditional refetch.
	if !ok {
		c.logger.Warn(ctx,
			"Resource reported unchanged but nothing is cached",
		)
		c.mu.Lock()
		c.etag, c.lastModified = "", ""
		c.mu.Unlock()
		return c.retry(ctx)
	}

	c.logger.Debug(ctx,
		"Resource unchanged",
		log.String("etag", etag),
	)
	c.stats.unchanged.Inc()
	return c.refresh(res.Header)
}

// update handles a 200 response, replacing the cached value.
func (c *controller[T]) update(
	ctx context.Context,
	res *http.Response,
) time.Duration {
	body, err := io.ReadAll(res.Body)
	if err != nil {
		c.logger.Error(ctx,
			"Failed to read response body",
			log.Error(err),
		)
		return c.retry(ctx)
	}

	resource, err := c.mapper(&Response{
		Body:   body,
		Ctx:    ctx,
		Logger: c.logger,
	})
	if err != nil {
		c.logger.Error(ctx,
			"Couldn't parse response body",
			log.Error(err),
		)
		return c.retry(ctx)
	}

	c.mu.Lock()
	c.resource = resource
	c.etag = header.ETag(res.Header)
	c.lastModified = res.Header.Get("Last-Modified")
	c.ok = true
	c.failures = 0
	c.mu.Unlock()

	c.logger.Info(ctx, "Resource updated successfully")
	c.stats.updated.Inc()

	// Signalled only once a value is actually available, so that consumers
	// blocked on Ready are guaranteed a hit from Get.
	c.ready()
	return c.refresh(res.Header)
}

// close releases the response body.
func (c *controller[T]) close(res *http.Response) {
	if err := res.Body.Close(); err != nil {
		c.logger.Warn(res.Request.Context(),
			"Failed to close response body",
			log.Error(err),
		)
	}
}

// refresh calculates the duration until the next fetch based on caching
// headers, clamped by the configured min/max intervals and optionally
// scattered by jitter.
func (c *controller[T]) refresh(h http.Header) time.Duration {
	c.mu.Lock()
	c.failures = 0
	c.mu.Unlock()

	d := header.Lifetime(h, c.now)
	d = min(max(d, c.minInterval), c.maxInterval)
	return c.jitter.Apply(d)
}

// retry records a failed refresh and returns the delay before the next
// attempt, which grows with the number of consecutive failures. It is the
// single sink for every failure path, so it also counts the cycle as an
// error.
func (c *controller[T]) retry(ctx context.Context) time.Duration {
	c.stats.failed.Inc()

	c.mu.Lock()
	c.failures++
	n := c.failures
	c.mu.Unlock()

	d := c.backoff.Delay(n)
	c.logger.Debug(ctx,
		"Scheduling a retry",
		log.Int("failures", n),
		log.Duration("delay", d),
	)
	return d
}

var _ Controller[any] = (*controller[any])(nil)
