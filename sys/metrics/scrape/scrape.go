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

// Package scrape collects metric snapshots from the /metrics endpoints of
// multiple application instances and merges them into a summary view.
//
// A [Collector] holds a set of named targets, each pointing at a collection
// endpoint served by [github.com/deep-rent/nexus/metrics.Registry.Handler].
// One sweep fetches every target concurrently and retains the latest
// snapshot per target; [Collector.Summary] merges them, tagging each sample
// with its instance and aggregating counter-like samples across instances.
//
// # Usage
//
// The collector performs one sweep per [Collector.Run] call, which
// implements [schedule.Task], so scheduling is the scheduler's business:
//
//	c := scrape.New()
//	c.Add("api-1", "http://10.0.0.1:8080/metrics")
//	c.Add("api-2", "http://10.0.0.2:8080/metrics")
//
//	s := schedule.New(ctx)
//	s.Dispatch(schedule.Named("scrape", schedule.Every(15*time.Second, c)))
//
// Mount the merged view on a router to expose it:
//
//	c.Mount(r) // GET /metrics
package scrape

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/sys/metrics"
	"github.com/deep-rent/nexus/sys/schedule"
	"github.com/deep-rent/nexus/net/transport"
)


// maxBody caps how many bytes of a snapshot response are read, so that a
// misbehaving target cannot exhaust the collector.
const maxBody = 8 << 20 // 8 MB


// target is one registered collection endpoint together with its latest
// scrape result.
type target struct {
	name string
	url  string

	mu       sync.Mutex
	snapshot *metrics.Snapshot // nil until the first successful scrape
	scraped  time.Time         // when the last attempt finished
	took     time.Duration     // duration of the last attempt
	err      error             // outcome of the last attempt
}

// Collector scrapes a set of collection endpoints; see the package
// documentation.
type Collector struct {
	client  *http.Client
	logger  *slog.Logger
	timeout time.Duration

	mu      sync.RWMutex
	targets []*target
	seen    map[string]struct{}
}

// New creates a [Collector] with no targets.
func New(opts ...Option) *Collector {
	cfg := config{
		client:  transport.NewClient(0),
		logger:  slog.Default(),
		timeout: DefaultTimeout,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Collector{
		client:  cfg.client,
		logger:  cfg.logger,
		timeout: cfg.timeout,
		seen:    make(map[string]struct{}),
	}
}

// Add registers a collection endpoint under an instance name, which tags the
// target's samples in the summary. Adding a name twice panics: two targets
// with one name would silently shadow each other in the summary.
func (c *Collector) Add(name, url string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.seen[name]; ok {
		panic(fmt.Sprintf("scrape: target %q already registered", name))
	}
	c.seen[name] = struct{}{}
	c.targets = append(c.targets, &target{name: name, url: url})
}

// Run performs one concurrent sweep over all targets, retaining the latest
// snapshot per target. It implements [schedule.Task], so a scheduler can
// drive it periodically; see the package documentation.
func (c *Collector) Run(ctx context.Context) {
	c.mu.RLock()
	targets := c.targets
	c.mu.RUnlock()

	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Go(func() {
			c.scrape(ctx, t)
		})
	}
	wg.Wait()
}

// scrape fetches one target and records the outcome.
func (c *Collector) scrape(ctx context.Context, t *target) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	start := time.Now()
	snapshot, err := c.fetch(ctx, t.url)
	took := time.Since(start)

	if err != nil {
		c.logger.WarnContext(ctx,
			"Scrape failed",
			slog.String("target", t.name),
			slog.String("url", t.url),
			log.Err(err),
		)
	}

	t.mu.Lock()
	t.scraped = time.Now()
	t.took = took
	t.err = err
	if err == nil {
		t.snapshot = snapshot
	}
	t.mu.Unlock()
}

// fetch retrieves and decodes a snapshot.
func (c *Collector) fetch(
	ctx context.Context,
	url string,
) (*metrics.Snapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			c.logger.WarnContext(
				ctx,
				"Failed to close response body",
				log.Err(err),
			)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", res.StatusCode)
	}

	var snapshot metrics.Snapshot
	body := io.LimitReader(res.Body, maxBody)
	if err := json.UnmarshalRead(body, &snapshot); err != nil {
		return nil, fmt.Errorf("decoding snapshot: %w", err)
	}
	return &snapshot, nil
}

var _ schedule.Task = (*Collector)(nil)
