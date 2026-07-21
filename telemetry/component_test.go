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

package telemetry_test

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/deep-rent/nexus/app"
)

func TestComponent_FlushesOnShutdown(t *testing.T) {
	tel, spans, _ := newTelemetry(t)

	// The component runs under the app runner; canceling the parent context
	// triggers the shutdown that must flush the batched span.
	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		done <- app.Run(
			app.Named("telemetry", tel.Component()),
			app.WithContext(ctx),
			app.WithSignals(), // The test process must keep its signals.
		)
	}()

	_, span := otel.Tracer("test").Start(t.Context(), "op")
	span.End()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not return after cancellation")
	}

	// The batch processor holds spans until flushed; the component's
	// shutdown is what delivers them to the exporter.
	if got := len(spans.GetSpans()); got != 1 {
		t.Errorf("spans: got %d; want 1", got)
	}
}
