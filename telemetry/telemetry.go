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

// Package telemetry wires the OpenTelemetry SDK into an application.
//
// The instrumented packages of this module (middleware, transport, router,
// schedule, event, migrate, cache, throttle) emit spans and metrics through
// the global OpenTelemetry providers, which are no-ops until something
// registers real ones. This package is that something: [New] builds a tracer
// and a meter provider backed by OTLP exporters, registers them globally,
// and returns a [Telemetry] handle that flushes and shuts everything down.
//
// This is the only package in the module that imports the OpenTelemetry SDK;
// the instrumented packages depend solely on the lightweight API. An
// application that never calls [New] therefore carries no telemetry runtime
// cost.
//
// # Usage
//
//	tel, err := telemetry.New(ctx,
//		telemetry.WithServiceName("api"),
//		telemetry.WithServiceVersion(version),
//	)
//	if err != nil {
//		return err
//	}
//
//	err = app.RunStages([]app.Stage{
//		{app.Named("telemetry", tel.Component())},
//		{app.Named("server", server)},
//	})
//
// Placing the component in the first stage matters: stages shut down in
// reverse order, so the providers outlive the components that emit into
// them, and the final flush happens after the last span has ended.
//
// # Configuration
//
// Exporters and providers honor the standard OTEL_* environment variables
// natively, most importantly OTEL_EXPORTER_OTLP_ENDPOINT (and its _TRACES_/
// _METRICS_ variants, headers, timeouts, and TLS settings),
// OTEL_TRACES_SAMPLER / OTEL_TRACES_SAMPLER_ARG, OTEL_RESOURCE_ATTRIBUTES,
// OTEL_METRIC_EXPORT_INTERVAL, and the OTEL_BSP_* batching knobs. This
// package adds two variables the Go SDK does not implement itself:
//
//   - OTEL_SDK_DISABLED: any true value makes [New] install no-op providers.
//   - OTEL_SERVICE_NAME: read by the SDK resource detection; the value
//     passed to [WithServiceName] serves as the fallback.
//
// Export uses OTLP over HTTP/protobuf, so no gRPC stack is pulled in.
package telemetry

import (
	"context"
	"errors"
	"log/slog"

	"github.com/deep-rent/nexus/env"
	"github.com/deep-rent/nexus/log"
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
)

// envConfig carries the OTEL_* settings implemented by this package rather
// than by the SDK itself.
type envConfig struct {
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

	var ec envConfig
	if err := env.Unmarshal(&ec, env.WithPrefix("OTEL_")); err != nil {
		return nil, err
	}
	if ec.ServiceName != "" {
		cfg.service = ec.ServiceName
	}

	// Failures inside the SDK surface asynchronously; routing them through
	// the logger keeps them visible without crashing the application.
	logger := cfg.logger
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		logger.Warn("OpenTelemetry error", log.Err(err))
	}))
	otel.SetTextMapPropagator(cfg.propagator)

	if cfg.disabled || ec.SDKDisabled {
		t := &Telemetry{
			tracerProvider: tnoop.NewTracerProvider(),
			meterProvider:  mnoop.NewMeterProvider(),
		}
		otel.SetTracerProvider(t.tracerProvider)
		otel.SetMeterProvider(t.meterProvider)
		return t, nil
	}

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithAttributes(append(
			[]attribute.KeyValue{
				semconv.ServiceName(cfg.service),
				semconv.ServiceVersion(cfg.version),
			},
			cfg.attributes...,
		)...),
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
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
		sdkmetric.WithResource(res),
	)
	t.meterProvider = meterProvider
	t.shutdown = append(t.shutdown, meterProvider.Shutdown)

	otel.SetTracerProvider(t.tracerProvider)
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
