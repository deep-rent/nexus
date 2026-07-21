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
