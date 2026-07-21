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

package telemetry

import (
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// config holds the settings applied by [New].
type config struct {
	service      string
	version      string
	attributes   []attribute.KeyValue
	sampler      sdktrace.Sampler
	propagator   propagation.TextMapPropagator
	spanExporter sdktrace.SpanExporter
	metricReader sdkmetric.Reader
	logger       *slog.Logger
	disabled     bool
}

// Option configures [New].
type Option func(*config)

// WithServiceName sets the service.name resource attribute, the primary
// identity of the application in a telemetry backend. The OTEL_SERVICE_NAME
// environment variable takes precedence over this value.
func WithServiceName(name string) Option {
	return func(c *config) {
		c.service = name
	}
}

// WithServiceVersion sets the service.version resource attribute.
func WithServiceVersion(version string) Option {
	return func(c *config) {
		c.version = version
	}
}

// WithResourceAttributes appends attributes to the resource describing this
// application, alongside the detected host and SDK attributes.
func WithResourceAttributes(attrs ...attribute.KeyValue) Option {
	return func(c *config) {
		c.attributes = append(c.attributes, attrs...)
	}
}

// WithSampler sets the trace sampler. It defaults to sampling every trace
// while honoring the sampling decision of an incoming trace context
// (ParentBased/AlwaysOn). The OTEL_TRACES_SAMPLER environment variable is
// interpreted by the SDK and takes precedence. A nil value is ignored.
func WithSampler(s sdktrace.Sampler) Option {
	return func(c *config) {
		if s != nil {
			c.sampler = s
		}
	}
}

// WithPropagator replaces the default composite of W3C Trace Context and
// Baggage registered as the global propagator. A nil value is ignored.
func WithPropagator(p propagation.TextMapPropagator) Option {
	return func(c *config) {
		if p != nil {
			c.propagator = p
		}
	}
}

// WithSpanExporter replaces the OTLP span exporter, primarily so that tests
// can capture spans in memory. A nil value is ignored.
func WithSpanExporter(exp sdktrace.SpanExporter) Option {
	return func(c *config) {
		if exp != nil {
			c.spanExporter = exp
		}
	}
}

// WithMetricReader replaces the periodic OTLP metric reader, primarily so
// that tests can collect metrics manually. A nil value is ignored.
func WithMetricReader(r sdkmetric.Reader) Option {
	return func(c *config) {
		if r != nil {
			c.metricReader = r
		}
	}
}

// WithLogger sets the logger that receives errors surfaced asynchronously by
// the SDK, such as failed export batches. It defaults to [slog.Default]. A
// nil value is ignored.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithDisabled forces no-op providers regardless of the environment, for
// example from an application flag. Telemetry can also be disabled with the
// OTEL_SDK_DISABLED environment variable.
func WithDisabled(disabled bool) Option {
	return func(c *config) {
		c.disabled = disabled
	}
}
