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

package migrate_test

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/nexus/migrate"
	drvmock "github.com/deep-rent/nexus/migrate/driver/mock"
	srcmock "github.com/deep-rent/nexus/migrate/source/mock"
)

// migrationAttr returns the string form of an attribute recorded on a span,
// or the empty string if the key is absent.
func migrationAttr(s sdktrace.ReadOnlySpan, key attribute.Key) string {
	for _, kv := range s.Attributes() {
		if kv.Key == key {
			return kv.Value.Emit()
		}
	}
	return ""
}

func TestMigrator_TracesRuns(t *testing.T) {
	t.Parallel()

	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	src := srcmock.New(
		migrate.SourceScript{
			Version:   1,
			Direction: migrate.Up,
			Content:   []byte("CREATE TABLE users;"),
		},
		migrate.SourceScript{
			Version:   2,
			Direction: migrate.Up,
			Content:   []byte("CREATE TABLE posts;"),
		},
	)
	m := migrate.New(
		migrate.WithSource(src),
		migrate.WithDriver(drvmock.New()),
		migrate.WithTracerProvider(tp),
	)

	if err := m.Up(t.Context()); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	ended := spans.Ended()
	if len(ended) != 2 {
		t.Fatalf("spans: got %d; want 2", len(ended))
	}

	if got, want := ended[0].Name(), "migrate up 1"; got != want {
		t.Errorf("name: got %q; want %q", got, want)
	}
	if got, want := ended[1].Name(), "migrate up 2"; got != want {
		t.Errorf("name: got %q; want %q", got, want)
	}
	if got := migrationAttr(ended[0], "migration.version"); got != "1" {
		t.Errorf("version attr: got %q; want %q", got, "1")
	}
	if got := migrationAttr(ended[0], "migration.direction"); got != "up" {
		t.Errorf("direction attr: got %q; want %q", got, "up")
	}
	if got := ended[0].Status().Code; got == codes.Error {
		t.Errorf("status: got %v; want not %v", got, codes.Error)
	}
}

func TestMigrator_TracesFailure(t *testing.T) {
	t.Parallel()

	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	src := srcmock.New(
		migrate.SourceScript{
			Version:   1,
			Direction: migrate.Up,
			Content:   []byte("CREATE TABLE users;"),
		},
	)
	drv := drvmock.New()
	drv.ExecuteErr = errors.New("syntax error")

	m := migrate.New(
		migrate.WithSource(src),
		migrate.WithDriver(drv),
		migrate.WithLogger(log.Silent()),
		migrate.WithTracerProvider(tp),
	)

	if err := m.Up(t.Context()); err == nil {
		t.Fatal("should have returned an error")
	}

	ended := spans.Ended()
	if len(ended) != 1 {
		t.Fatalf("spans: got %d; want 1", len(ended))
	}
	if got := ended[0].Status().Code; got != codes.Error {
		t.Errorf("status: got %v; want %v", got, codes.Error)
	}
	if len(ended[0].Events()) == 0 {
		t.Error("events: got none; want a recorded exception")
	}
}
