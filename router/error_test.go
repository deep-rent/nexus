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

package router_test

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/nexus/router"
)

// exercise runs a handler through a router and returns the response together
// with everything the router logged.
func exercise(
	t *testing.T,
	fn func(*router.Exchange) error,
	level slog.Level,
) (*httptest.ResponseRecorder, string) {
	t.Helper()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: level,
	}))

	r := router.New(router.WithLogger(logger))
	r.HandleFunc("GET /resource", fn)

	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodGet, "/resource", nil,
	)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	return rec, buf.String()
}

// decode reads the error body the router wrote.
func decode(t *testing.T, rec *httptest.ResponseRecorder) *router.Error {
	t.Helper()

	var got router.Error
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding body %q: %v", rec.Body.String(), err)
	}
	return &got
}

// A handler that returns an *Error must be logged by the router, so that no
// handler has to log on its own.
func TestErrorHandler_LogsHandlerErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		err   *router.Error
		level slog.Level
		want  []string
	}{
		{
			name: "server error",
			err: router.ServerError(
				"The document store is unreachable.",
				errors.New("dial tcp: connection refused"),
			),
			level: slog.LevelError,
			want: []string{
				"level=ERROR",
				"The document store is unreachable.",
				"status=500",
				"reason=server_error",
				"method=GET",
				"path=/resource",
				"error_id=",
				"dial tcp: connection refused",
			},
		},
		{
			name:  "client error",
			err:   router.Invalid("The document ID is not a valid UUID."),
			level: slog.LevelDebug,
			want: []string{
				"level=DEBUG",
				"The document ID is not a valid UUID.",
				"status=400",
				"reason=validation_failed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, logs := exercise(t, func(*router.Exchange) error {
				return tt.err
			}, tt.level)

			for _, want := range tt.want {
				if !strings.Contains(logs, want) {
					t.Errorf("want match for %q; got %q", want, logs)
				}
			}
		})
	}
}

// Client errors are ordinary traffic and must not be logged at error level.
func TestErrorHandler_ClientErrorsAreNotErrors(t *testing.T) {
	t.Parallel()

	_, logs := exercise(t, func(*router.Exchange) error {
		return router.NotFound("No such document.")
	}, slog.LevelDebug)

	if strings.Contains(logs, "level=ERROR") {
		t.Errorf("client error logged at error level: %q", logs)
	}
}

// The identifier a client reports back must be findable in the logs.
func TestErrorHandler_ServerErrorCarriesID(t *testing.T) {
	t.Parallel()

	rec, logs := exercise(t, func(*router.Exchange) error {
		return router.ServerError("Something broke.", errors.New("boom"))
	}, slog.LevelError)

	got := decode(t, rec)

	if got.ID == "" {
		t.Fatal("response carries no error ID")
	}

	if !strings.Contains(logs, got.ID) {
		t.Errorf("error ID %q not found in logs %q", got.ID, logs)
	}
}

// An ID set by the caller must be preserved rather than replaced.
func TestErrorHandler_PreservesExistingID(t *testing.T) {
	t.Parallel()

	const id = "01234567-89ab-cdef-0123-456789abcdef"

	rec, _ := exercise(t, func(*router.Exchange) error {
		e := router.ServerError("Something broke.", errors.New("boom"))
		e.ID = id
		return e
	}, slog.LevelError)

	if got := decode(t, rec).ID; got != id {
		t.Errorf("got %q; want %q", got, id)
	}
}

// Client errors are not worth an identifier, and minting one per 404 would be
// wasted work on a public API.
func TestErrorHandler_ClientErrorHasNoID(t *testing.T) {
	t.Parallel()

	rec, _ := exercise(t, func(*router.Exchange) error {
		return router.NotFound("No such document.")
	}, slog.LevelDebug)

	if got := decode(t, rec).ID; got != "" {
		t.Errorf("got %q; want no ID", got)
	}
}

// A plain error carries no client-facing shape and must not leak its text.
func TestErrorHandler_OpaqueInternalError(t *testing.T) {
	t.Parallel()

	const secret = "postgres://user:hunter2@db.internal:5432"

	rec, logs := exercise(t, func(*router.Exchange) error {
		return errors.New(secret)
	}, slog.LevelError)

	if got := rec.Code; got != http.StatusInternalServerError {
		t.Errorf("status: got %d; want 500", got)
	}

	if body := rec.Body.String(); strings.Contains(body, secret) {
		t.Errorf("internal detail leaked to the client: %q", body)
	}

	// It must still reach the logs, where it is needed.
	if !strings.Contains(logs, secret) {
		t.Errorf("cause missing from logs: %q", logs)
	}
}

// The cause is for the logs only; the description is what the client sees.
func TestError_CauseIsNotSerialized(t *testing.T) {
	t.Parallel()

	const secret = "table `users` does not exist"

	rec, _ := exercise(t, func(*router.Exchange) error {
		return router.ServerError("Try again later.", errors.New(secret))
	}, slog.LevelError)

	if body := rec.Body.String(); strings.Contains(body, secret) {
		t.Errorf("cause leaked to the client: %q", body)
	}
}

func TestErrorHandler_AfterResponseWritten(t *testing.T) {
	t.Parallel()

	_, logs := exercise(t, func(e *router.Exchange) error {
		err := e.JSON(http.StatusOK, map[string]string{"ok": "yes"})
		if err != nil {
			return err
		}
		return errors.New("too late")
	}, slog.LevelError)

	if want := "after writing response"; !strings.Contains(logs, want) {
		t.Errorf("want match for %q; got %q", want, logs)
	}
}

func TestErrorConstructors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        *router.Error
		wantStatus int
		wantReason string
	}{
		{
			"fail",
			router.Fail(http.StatusTeapot, "teapot", "I am a teapot."),
			http.StatusTeapot,
			"teapot",
		},
		{
			"not found",
			router.NotFound("Gone."),
			http.StatusNotFound,
			router.ReasonNotFound,
		},
		{
			"invalid",
			router.Invalid("Bad input."),
			http.StatusBadRequest,
			router.ReasonValidationFailed,
		},
		{
			"server error",
			router.ServerError("Oops.", errors.New("cause")),
			http.StatusInternalServerError,
			router.ReasonServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.err.Status; got != tt.wantStatus {
				t.Errorf("status: got %d; want %d", got, tt.wantStatus)
			}

			if got := tt.err.Reason; got != tt.wantReason {
				t.Errorf("reason: got %q; want %q", got, tt.wantReason)
			}
		})
	}
}

func TestError_Builders(t *testing.T) {
	t.Parallel()

	cause := errors.New("underlying")
	detail := map[string]string{"field": "required"}

	err := router.Invalid("Bad input.").
		WithCause(cause).
		WithContext(detail)

	if !errors.Is(err, cause) {
		t.Errorf("cause: got %v; want %v", err.Cause, cause)
	}

	if err.Context == nil {
		t.Error("context: got nil; want the attached detail")
	}
}

// A silent logger must not be paid for: nothing is formatted when the level
// is disabled.
func TestErrorHandler_RespectsLogLevel(t *testing.T) {
	t.Parallel()

	_, logs := exercise(t, func(*router.Exchange) error {
		return router.NotFound("No such document.")
	}, slog.LevelError)

	if logs != "" {
		t.Errorf("got %q; want nothing logged below the level", logs)
	}
}

// The log package is the repo's logger constructor; this keeps the import
// used and guards the wiring end to end.
func TestErrorHandler_WithConstructedLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := log.New(
		log.WithLevel(slog.LevelError),
		log.WithFormat(log.FormatJSON),
		log.WithWriter(&buf),
	)

	r := router.New(router.WithLogger(logger))
	r.HandleFunc("GET /boom", func(*router.Exchange) error {
		return errors.New("boom")
	})

	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodGet, "/boom", nil,
	)
	r.ServeHTTP(httptest.NewRecorder(), req)

	if want := `"error_id"`; !strings.Contains(buf.String(), want) {
		t.Errorf("want match for %q; got %q", want, buf.String())
	}
}
