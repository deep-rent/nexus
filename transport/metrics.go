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
	"net/http"
	"strconv"
	"time"

	"github.com/deep-rent/nexus/metrics"
)

// RequestDuration is the name of the histogram recorded by the metrics
// transport; see [WithMetrics].
const RequestDuration = "http_client_request_duration_seconds"

// metricsConfig holds the configuration for a metrics transport.
type metricsConfig struct {
	registry *metrics.Registry
}

// MetricsOption configures a metrics transport created by
// [NewMetricsTransport] or enabled via [WithMetrics].
type MetricsOption func(*metricsConfig)

// WithRegistry sets the destination registry. It defaults to
// [metrics.DefaultRegistry]. A nil value is ignored.
func WithRegistry(reg *metrics.Registry) MetricsOption {
	return func(c *metricsConfig) {
		if reg != nil {
			c.registry = reg
		}
	}
}

// metricsTransport wraps an underlying [http.RoundTripper] with request
// measurement.
type metricsTransport struct {
	next     http.RoundTripper
	registry *metrics.Registry
}

// NewMetricsTransport wraps a transport so that every round trip is recorded
// in the [RequestDuration] histogram, tagged with the request method, the
// target host, and the response status code — or "error" when the exchange
// failed without a response.
//
// When layered below a [retry.NewTransport] — the placement chosen by
// [WithMetrics] — each retry attempt is recorded as its own observation, so
// the histogram reflects wire activity rather than logical requests.
func NewMetricsTransport(
	next http.RoundTripper,
	opts ...MetricsOption,
) http.RoundTripper {
	cfg := metricsConfig{registry: metrics.DefaultRegistry}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &metricsTransport{next: next, registry: cfg.registry}
}

// RoundTrip executes a single HTTP transaction and records its duration.
func (t *metricsTransport) RoundTrip(
	req *http.Request,
) (*http.Response, error) {
	start := time.Now()
	res, err := t.next.RoundTrip(req)

	status := "error"
	if err == nil {
		status = strconv.Itoa(res.StatusCode)
	}
	t.registry.Histogram(RequestDuration, nil,
		metrics.T("method", req.Method),
		metrics.T("host", req.URL.Hostname()),
		metrics.T("status", status),
	).Observe(time.Since(start).Seconds())

	return res, err
}

var _ http.RoundTripper = (*metricsTransport)(nil)
