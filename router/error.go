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

package router

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"uuid"
)

// Error describes the standardized shape of API errors returned to clients.
//
// Handlers can return this struct directly to control the HTTP status code
// and error details. If a handler returns a standard Go error, the [Router]
// will wrap it in a generic internal server error.
//
// Handlers should not log the errors they return. The [Router] logs every
// error centrally, with the request attributes attached; see [WithLogger].
type Error struct {
	// Status is the HTTP status code (e.g., 400, 404, 500).
	Status int `json:"status"`
	// Reason is a short string identifying the error type.
	Reason string `json:"reason"`
	// Description is a human-readable explanation of the error cause.
	Description string `json:"description"`
	// ID is a unique identifier of the specific occurrence for tracing. The
	// router fills it in for server errors, so that the value a client
	// reports can be found in the logs.
	ID string `json:"id,omitempty"`
	// Context contains arbitrary additional data about the error.
	Context any `json:"context,omitempty"`
	// Cause is the underlying error that triggered this error. It is logged
	// but never serialized, so it may carry internal detail.
	Cause error `json:"-"`
}

// Error satisfies the standard [error] interface.
func (e *Error) Error() string {
	return e.Reason + ": " + e.Description
}

// Unwrap returns the wrapped error if applicable.
func (e *Error) Unwrap() error {
	return e.Cause
}

// WithCause attaches the underlying cause of the error and returns the
// receiver, so that it can be chained onto a constructor. The cause is logged
// by the router but never sent to the client.
func (e *Error) WithCause(err error) *Error {
	e.Cause = err
	return e
}

// WithContext attaches arbitrary structured detail to the error and returns
// the receiver, so that it can be chained onto a constructor. Unlike the
// cause, this data is serialized to the client, so it must not carry
// internals.
func (e *Error) WithContext(ctx any) *Error {
	e.Context = ctx
	return e
}

var _ error = (*Error)(nil)

// Fail builds an [Error] with the given status, reason and description. Use
// the chainable [Error.WithCause] and [Error.WithContext] to add detail:
//
//	return router.Fail(
//		http.StatusBadRequest,
//		router.ReasonValidationFailed,
//		"The document ID is not a valid UUID.",
//	).WithContext(valid.Error{"id": {"must be a valid UUID"}})
func Fail(status int, reason, description string) *Error {
	return &Error{
		Status:      status,
		Reason:      reason,
		Description: description,
	}
}

// NotFound builds a 404 [Error]. Endpoints should prefer it over a bespoke
// 403 when hiding the existence of a resource, so that callers cannot probe
// for identifiers they have no access to.
func NotFound(description string) *Error {
	return Fail(http.StatusNotFound, ReasonNotFound, description)
}

// Invalid builds a 400 [Error] describing input that failed validation.
func Invalid(description string) *Error {
	return Fail(http.StatusBadRequest, ReasonValidationFailed, description)
}

// ServerError builds a 500 [Error] carrying the given cause. The description
// reaches the client, so it must stay free of internal detail; the cause is
// logged by the router instead.
func ServerError(description string, cause error) *Error {
	return Fail(
		http.StatusInternalServerError,
		ReasonServerError,
		description,
	).WithCause(cause)
}

// ErrorID generates a unique, string-based identifier intended for use
// in the [Error.ID] field.
//
// This identifier helps correlate client-side error reports with server-side
// logs, making it easier to trace the specific occurrence of an issue
// through the system. The [Router] assigns one to every server error, so
// handlers rarely need to call this directly.
func ErrorID() string {
	return uuid.NewV7().String()
}

// defaultErrorHandler centralizes error processing: it normalizes whatever a
// handler returned into an [Error], logs it once with the request attributes
// attached, and writes the JSON response.
//
// Logging every error here, rather than at each site that builds one, is what
// keeps handlers free of logging boilerplate and keeps the log record shape
// consistent across the application.
func defaultErrorHandler(logger *slog.Logger) ErrorHandler {
	return func(e *Exchange, err error) {
		ctx := e.Context()

		// Nothing can be sent once the response is on the wire, so the error
		// is only recorded.
		if e.W.Closed() {
			logger.ErrorContext(ctx,
				"Handler returned error after writing response",
				slog.Any("error", err),
				slog.String("method", e.Method()),
				slog.String("path", e.Path()),
			)
			return
		}

		res := &Error{}
		if !errors.As(err, &res) {
			// An error that is not an *Error carries no client-facing shape,
			// so it is reported as an opaque internal failure.
			res = ServerError(
				"an unhandled internal error occurred",
				err,
			)
		}

		// A server error is the kind a client may report back, so it always
		// carries an identifier that can be found in the logs.
		if res.ID == "" && res.Status >= http.StatusInternalServerError {
			res.ID = ErrorID()
		}

		record(ctx, logger, e, res)

		if werr := e.JSON(res.Status, res); werr != nil {
			logger.WarnContext(ctx,
				"Failed to write error response",
				slog.Any("error", werr),
			)
		}
	}
}

// record logs a failed exchange. Server errors are reported at error level,
// since they demand attention; client errors are ordinary traffic on a public
// API and would otherwise drown the logs, so they are recorded at debug level.
func record(
	ctx context.Context,
	logger *slog.Logger,
	e *Exchange,
	res *Error,
) {
	level := slog.LevelDebug
	if res.Status >= http.StatusInternalServerError {
		level = slog.LevelError
	}

	if !logger.Enabled(ctx, level) {
		return
	}

	attrs := []any{
		slog.Int("status", res.Status),
		slog.String("reason", res.Reason),
		slog.String("method", e.Method()),
		slog.String("path", e.Path()),
	}
	if res.ID != "" {
		attrs = append(attrs, slog.String("error_id", res.ID))
	}
	// The cause carries the internal detail that the description withholds
	// from the client.
	if res.Cause != nil {
		attrs = append(attrs, slog.Any("error", res.Cause))
	}

	logger.Log(ctx, level, res.Description, attrs...)
}
