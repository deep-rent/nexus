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
	"context"
	"errors"
	"log/slog"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	mnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"
	tnoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/deep-rent/nexus/env"
	"github.com/deep-rent/nexus/log"
)

// environment carries the OTEL_* settings implemented by this package rather
// than by the SDK itself.
type environment struct {
	// SDKDisabled turns New into a no-op, per the OpenTelemetry
	// specification's OTEL_SDK_DISABLED.
	SDKDisabled bool `env:"SDK_DISABLED"`
	// ServiceName overrides the service name passed to WithServiceName.
	ServiceName string `env:"SERVICE_NAME"`
}

// Telemetry holds the configured OpenTelemetry providers and their shutdown
// hooks. Create one with [New].
type Telemetry struct {
	tracerProvider trace.TracerProvider
	meterProvider  metric.MeterProvider
	shutdown       []func(ctx context.Context) error
}

// New builds the OpenTelemetry SDK from the given options and the OTEL_*
// environment (see the package documentation), registers the resulting
// providers and propagator as the otel globals, and returns a handle for
// shutting them down.
//
// When telemetry is disabled — via [WithDisabled] or OTEL_SDK_DISABLED —
// no-op providers are built and registered instead, and the returned
// handle's [Telemetry.Shutdown] does nothing. Call sites therefore never
// need to special-case the disabled path.
//
// The context governs the setup of the OTLP exporters, not the lifetime of
// the providers; cancel it only to abort initialization.
func New(ctx context.Context, opts ...Option) (*Telemetry, error) {
	cfg := config{
		logger:  slog.Default(),
		sampler: sdktrace.ParentBased(sdktrace.AlwaysSample()),
		propagator: propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	var e environment
	if err := env.Unmarshal(&e, env.WithPrefix("OTEL_")); err != nil {
		return nil, err
	}
	if e.ServiceName != "" {
		cfg.service = e.ServiceName
	}

	// Failures inside the SDK surface asynchronously; routing them through
	// the logger keeps them visible without crashing the application.
	logger := cfg.logger
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		logger.Warn("OpenTelemetry error", log.Err(err))
	}))
	// The SDK's internal diagnostics — dropped batches, exporter retries,
	// misconfiguration warnings — flow through a separate logr logger and
	// would otherwise be swallowed. The bridge maps logr verbosity onto
	// slog levels below LevelInfo (warnings at -1, info at -4, debug at
	// -8), so the chatter stays hidden unless the handler lowers its level
	// to listen for it.
	otel.SetLogger(logr.FromSlogHandler(logger.Handler()))
	otel.SetTextMapPropagator(cfg.propagator)

	if cfg.disabled || e.SDKDisabled {
		t := &Telemetry{
			tracerProvider: tnoop.NewTracerProvider(),
			meterProvider:  mnoop.NewMeterProvider(),
		}
		otel.SetTracerProvider(t.tracerProvider)
		otel.SetMeterProvider(t.meterProvider)
		return t, nil
	}

	// Service attributes are added only when set: WithAttributes outranks
	// the detectors before it, so an empty value would wipe out a
	// service.name or service.version provided via OTEL_RESOURCE_ATTRIBUTES.
	attrs := make([]attribute.KeyValue, 0, len(cfg.attributes)+2)
	if cfg.service != "" {
		attrs = append(attrs, semconv.ServiceName(cfg.service))
	}
	if cfg.version != "" {
		attrs = append(attrs, semconv.ServiceVersion(cfg.version))
	}
	attrs = append(attrs, cfg.attributes...)

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithAttributes(attrs...),
	)
	if err != nil {
		return nil, err
	}

	t := &Telemetry{}

	spanExporter := cfg.spanExporter
	if spanExporter == nil {
		spanExporter, err = otlptracehttp.New(ctx)
		if err != nil {
			return nil, err
		}
	}
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(spanExporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(cfg.sampler),
	)
	t.tracerProvider = tracerProvider
	t.shutdown = append(t.shutdown, tracerProvider.Shutdown)

	reader := cfg.metricReader
	if reader == nil {
		metricExporter, err := otlpmetrichttp.New(ctx)
		if err != nil {
			// The tracer provider is already running; roll it back so that no
			// goroutines leak from the failed setup.
			err = errors.Join(err, tracerProvider.Shutdown(ctx))
			return nil, err
		}
		reader = sdkmetric.NewPeriodicReader(metricExporter)
	}

	otel.SetTracerProvider(t.tracerProvider)

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
		sdkmetric.WithResource(res),
	)
	t.meterProvider = meterProvider
	t.shutdown = append(t.shutdown, meterProvider.Shutdown)

	otel.SetMeterProvider(t.meterProvider)

	return t, nil
}

// TracerProvider returns the configured tracer provider. It is also
// registered as the otel global, so instrumented packages pick it up without
// explicit wiring.
func (t *Telemetry) TracerProvider() trace.TracerProvider {
	return t.tracerProvider
}

// MeterProvider returns the configured meter provider. It is also registered
// as the otel global, so instrumented packages pick it up without explicit
// wiring.
func (t *Telemetry) MeterProvider() metric.MeterProvider {
	return t.meterProvider
}

// Shutdown flushes all pending spans and metrics and stops the providers.
// It must be called before the process exits, or buffered telemetry is
// lost; [Telemetry.Component] does this at the right point of the
// application lifecycle. The errors of both providers are joined.
func (t *Telemetry) Shutdown(ctx context.Context) error {
	errs := make([]error, 0, len(t.shutdown))
	for _, stop := range t.shutdown {
		errs = append(errs, stop(ctx))
	}
	return errors.Join(errs...)
}
