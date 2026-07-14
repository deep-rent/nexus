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

// Package router provides a lightweight, JSON-centric wrapper around Go's
// native [http.ServeMux].
//
// It simplifies building JSON APIs by offering a consolidated "Exchange" object
// for handling requests and responses, standardized error formatting, and a
// middleware chaining mechanism.
//
// # Basic Usage
//
// 1. Setup the router with options:
//
// Example:
//
//	logger := log.New()
//	r := router.New(
//	  router.WithLogger(logger),
//	  router.WithMiddleware(router.Log(logger)),
//	)
//
// 2. Define a handler:
//
// Example:
//
//	r.HandleFunc("POST /users", func(e *router.Exchange) error {
//	  var req CreateUserRequest
//	  if err := e.BindJSON(&req); err != nil {
//	    return err
//	  }
//	  return e.JSON(http.StatusCreated, UserResponse{ID: "123"})
//	})
//
// 3. Start the server:
//
// Example:
//
//	http.ListenAndServe(":8080", r)
package router

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"uuid"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/internal/bind"
	"github.com/deep-rent/nexus/internal/snake"
	"github.com/deep-rent/nexus/middleware"
	"github.com/deep-rent/nexus/middleware/cors"
	"github.com/deep-rent/nexus/middleware/gzip"
	"github.com/deep-rent/nexus/valid"
)

// Standard error reasons used for machine-readable error codes.
const (
	// ReasonWrongType indicates that the request had an unsupported content
	// type.
	ReasonWrongType = "wrong_type"
	// ReasonEmptyBody indicates that the request body was empty.
	ReasonEmptyBody = "empty_body"
	// ReasonParseJSON indicates that there was an error parsing the JSON body.
	ReasonParseJSON = "parse_json"
	// ReasonParseForm indicates that there was an error parsing form data.
	ReasonParseForm = "parse_form"
	// ReasonParseQuery indicates that there was an error parsing query
	// parameters.
	ReasonParseQuery = "parse_query"
	// ReasonValidationFailed indicates that input validation failed.
	ReasonValidationFailed = "validation_failed"
	// ReasonServerError indicates that an unexpected internal error occurred.
	ReasonServerError = "server_error"
)

// Standard media types used in the Content-Type header.
const (
	// MediaTypeJSON is the media type for JSON content.
	MediaTypeJSON = "application/json"
	// MediaTypeForm is the media type for URL-encoded form data.
	MediaTypeForm = "application/x-www-form-urlencoded"
)

var formBinder = bind.New(
	"form",
	bind.WithCache(true),
	bind.WithTransformer(snake.ToLower),
)

type urlSource url.Values

func (s urlSource) Lookup(key string) ([]string, bool) {
	v, ok := s[key]
	return v, ok
}

var _ bind.Source = (*urlSource)(nil)

// ResponseWriter extends [http.ResponseWriter] with introspection capabilities.
//
// It allows handlers and middleware to check if the response headers have
// already been written, which is crucial for robust error handling.
type ResponseWriter interface {
	http.ResponseWriter
	// Status returns the HTTP status code written, or 0 if not written yet.
	Status() int
	// Closed reports whether the headers have already been written.
	Closed() bool
	// Unwrap returns the underlying [http.ResponseWriter].
	Unwrap() http.ResponseWriter
}

// NewResponseWriter wraps an [http.ResponseWriter] into a [ResponseWriter].
func NewResponseWriter(w http.ResponseWriter) ResponseWriter {
	return &responseWriter{
		ResponseWriter: w,
		status:         0,
	}
}

// responseWriter is the concrete implementation of [ResponseWriter].
type responseWriter struct {
	// ResponseWriter is the underlying standard writer.
	http.ResponseWriter
	// status stores the HTTP response code once committed.
	status int
}

// WriteHeader implements [ResponseWriter].
func (rw *responseWriter) WriteHeader(code int) {
	if rw.status != 0 {
		return
	}
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write implements [ResponseWriter].
func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.status == 0 {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// Status implements [ResponseWriter].
func (rw *responseWriter) Status() int {
	return rw.status
}

// Closed implements [ResponseWriter].
func (rw *responseWriter) Closed() bool {
	return rw.status != 0
}

// Unwrap implements [ResponseWriter].
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

var _ http.ResponseWriter = (*responseWriter)(nil)

// Error describes the standardized shape of API errors returned to clients.
//
// Handlers can return this struct directly to control the HTTP status code
// and error details. If a handler returns a standard Go error, the [Router]
// will wrap it in a generic internal server error.
type Error struct {
	// Status is the HTTP status code (e.g., 400, 404, 500).
	Status int `json:"status"`
	// Reason is a short string identifying the error type.
	Reason string `json:"reason"`
	// Description is a human-readable explanation of the error cause.
	Description string `json:"description"`
	// ID is a unique identifier of the specific occurrence for tracing.
	ID string `json:"id,omitempty"`
	// Context contains arbitrary additional data about the error.
	Context any `json:"context,omitempty"`
	// Cause is the underlying error that triggered this error.
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

// ErrorID generates a unique, string-based identifier intended for use
// in the [Error.ID] field.
//
// This identifier helps correlate client-side error reports with server-side
// logs, making it easier to trace the specific occurrence of an issue
// through the system.
func ErrorID() string {
	return uuid.NewV7().String()
}

// Exchange acts as a context object for a single HTTP request/response cycle.
//
// It wraps the underlying [*http.Request] and [http.ResponseWriter] to provide
// convenient helper methods for common API tasks, such as parsing JSON,
// reading parameters, and writing structured responses.
type Exchange struct {
	// R is the incoming HTTP request.
	R *http.Request
	// W is a writer for the outgoing HTTP response.
	W ResponseWriter
	// jsonOpts is inherited from the parent Router.
	jsonOpts []json.Options
	// errorHandler allows middlewares to trigger standardized error resolution.
	errorHandler ErrorHandler
}

// Context returns the request's context.
func (e *Exchange) Context() context.Context { return e.R.Context() }

// Method returns the HTTP method (GET, POST, etc.) of the request.
func (e *Exchange) Method() string { return e.R.Method }

// URL returns the full URL of the request.
func (e *Exchange) URL() *url.URL { return e.R.URL }

// Path returns the URL path of the request.
func (e *Exchange) Path() string { return e.R.URL.Path }

// Param retrieves a path parameter by name.
//
// This relies on Go 1.22+ routing patterns (e.g., "GET /users/{id}").
func (e *Exchange) Param(name string) string { return e.R.PathValue(name) }

// Query parses the URL query parameters of the request.
func (e *Exchange) Query() url.Values { return e.R.URL.Query() }

// Header returns the HTTP headers of the request.
func (e *Exchange) Header() http.Header { return e.R.Header }

// GetHeader retrieves a specific header value from the request.
func (e *Exchange) GetHeader(key string) string { return e.R.Header.Get(key) }

// SetHeader sets a specific header value in the response.
func (e *Exchange) SetHeader(key, value string) { e.W.Header().Set(key, value) }

// BindJSON decodes the request body into v.
//
// This method verifies that the media type is "application/json", checks that
// the payload is not empty, unmarshals the JSON, and validates the input using
// [valid.Test].
func (e *Exchange) BindJSON(v any) *Error {
	if t := header.MediaType(e.R.Header); t != MediaTypeJSON {
		return &Error{
			Status:      http.StatusUnsupportedMediaType,
			Reason:      ReasonWrongType,
			Description: "content-type must be " + MediaTypeJSON,
		}
	}
	if e.R.ContentLength == 0 || e.R.Body == nil || e.R.Body == http.NoBody {
		return &Error{
			Status:      http.StatusBadRequest,
			Reason:      ReasonEmptyBody,
			Description: "empty request body",
		}
	}

	if err := json.UnmarshalRead(e.R.Body, v, e.jsonOpts...); err != nil {
		return &Error{
			Status:      http.StatusBadRequest,
			Reason:      ReasonParseJSON,
			Description: "could not parse JSON body",
		}
	}

	if err := valid.Test(v); err != nil {
		count := err.Size()

		return &Error{
			Status:      http.StatusBadRequest,
			Reason:      ReasonValidationFailed,
			Description: fmt.Sprintf("input violates %d constraints", count),
			Context:     err,
		}
	}

	return nil
}

// BindQuery decodes URL query parameters into v.
func (e *Exchange) BindQuery(v any) *Error {
	q := e.R.URL.Query()
	if err := formBinder.Bind(v, "", urlSource(q)); err != nil {
		return &Error{
			Status:      http.StatusBadRequest,
			Reason:      ReasonParseQuery,
			Description: err.Error(),
		}
	}
	if err := valid.Test(v); err != nil {
		count := err.Size()

		return &Error{
			Status:      http.StatusBadRequest,
			Reason:      ReasonValidationFailed,
			Description: fmt.Sprintf("input violates %d constraints", count),
			Context:     err,
		}
	}
	return nil
}

// BindForm decodes URL-encoded form data from the request body into v.
func (e *Exchange) BindForm(v any) error {
	form, err := e.ReadForm()
	if err != nil {
		return err
	}
	if err := formBinder.Bind(v, "", urlSource(form)); err != nil {
		return &Error{
			Status:      http.StatusBadRequest,
			Reason:      ReasonParseForm,
			Description: err.Error(),
		}
	}
	if err := valid.Test(v); err != nil {
		count := err.Size()

		return &Error{
			Status:      http.StatusBadRequest,
			Reason:      ReasonValidationFailed,
			Description: fmt.Sprintf("input violates %d constraints", count),
			Context:     err,
		}
	}
	return nil
}

// ReadForm parses the request body as URL-encoded form data.
//
// Unlike standard [http.Request.FormValue], this strictly accesses the request
// body, ignoring URL query parameters.
func (e *Exchange) ReadForm() (url.Values, error) {
	if t := header.MediaType(e.R.Header); t != MediaTypeForm {
		return nil, &Error{
			Status:      http.StatusUnsupportedMediaType,
			Reason:      ReasonWrongType,
			Description: "content-type must be " + MediaTypeForm,
		}
	}
	if err := e.R.ParseForm(); err != nil {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Reason:      ReasonParseForm,
			Description: "malformed form data",
		}
	}
	return e.R.PostForm, nil
}

// JSON encodes v as JSON and writes it to the response.
//
// It automatically sets the Content-Type header to [MediaTypeJSON] if it has
// not already been set.
func (e *Exchange) JSON(code int, v any) error {
	buf, err := json.Marshal(v, e.jsonOpts...)
	if err != nil {
		return err
	}

	if e.W.Header().Get("Content-Type") == "" {
		e.SetHeader("Content-Type", MediaTypeJSON)
	}

	e.Status(code)

	_, err = e.W.Write(buf)
	return err
}

// Form writes the values as URL-encoded form data.
//
// It automatically sets the Content-Type header to [MediaTypeForm] if it has
// not already been set.
func (e *Exchange) Form(code int, v url.Values) error {
	if e.W.Header().Get("Content-Type") == "" {
		e.SetHeader("Content-Type", MediaTypeForm)
	}
	e.Status(code)
	_, err := e.W.Write([]byte(v.Encode()))
	return err
}

// Status sends an HTTP response header with the provided status code.
//
// Note: Calling this commits the response headers. It is primarily used for
// empty responses like HTTP 204 (No Content).
func (e *Exchange) Status(code int) {
	e.W.WriteHeader(code)
}

// NoContent sends a HTTP 204 No Content response.
func (e *Exchange) NoContent() {
	e.Status(http.StatusNoContent)
}

// Redirect replies to the request with a redirect to url.
func (e *Exchange) Redirect(url string, code int) error {
	http.Redirect(e.W, e.R, url, code)
	return nil
}

// Cookie retrieves a named cookie from the request.
// It returns [http.ErrNoCookie] if no such cookie was found.
// If multiple cookies match the given name, only one cookie will be returned.
func (e *Exchange) Cookie(name string) (*http.Cookie, error) {
	return e.R.Cookie(name)
}

// SetCookie adds a Set-Cookie header to the response.
// The provided cookie must have a valid name. Invalid cookies may be silently
// dropped.
func (e *Exchange) SetCookie(cookie *http.Cookie) {
	http.SetCookie(e.W, cookie)
}

// Handler defines the interface for HTTP request handlers used by the [Router].
type Handler interface {
	// ServeHTTP processes an HTTP request encapsulated in the Exchange object.
	ServeHTTP(e *Exchange) error
}

// HandlerFunc defines the function signature for HTTP request handlers.
type HandlerFunc func(e *Exchange) error

// ServeHTTP satisfies the [Handler] interface.
func (f HandlerFunc) ServeHTTP(e *Exchange) error { return f(e) }

var _ Handler = HandlerFunc(nil)

// ErrorHandler defines a function that handles errors returned by routes.
type ErrorHandler func(e *Exchange, err error)

// Middleware defines a function that wraps a [Handler].
//
// It allows custom logic to be executed before and/or after the next handler.
// Unlike standard HTTP middleware, this natively supports returning API errors.
type Middleware func(Handler) Handler

// Chain combines a handler with multiple [Middleware] functions.
//
// The functions are applied in reverse order, meaning the first middleware in
// the list is the outermost and executes first.
func Chain(h Handler, mws ...Middleware) Handler {
	for _, mw := range slices.Backward(mws) {
		if mw != nil {
			h = mw(h)
		}
	}
	return h
}

// Wrap converts a standard [http.Handler] into a router [Handler].
func Wrap(h http.Handler) Handler {
	return HandlerFunc(func(e *Exchange) error {
		h.ServeHTTP(e.W, e.R)
		return nil
	})
}

// Adapt converts a standard [middleware.Pipe] into a [Middleware].
//
// This bridges low-level HTTP transport middlewares into the router's
// ecosystem. It ensuring that any modifications made to the request or response
// writer by the transport middleware are preserved.
func Adapt(pipe middleware.Pipe) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(e *Exchange) error {
			var nextErr error

			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				e.R = r
				if rw, ok := w.(ResponseWriter); ok {
					e.W = rw
				} else {
					e.W = NewResponseWriter(w)
				}

				nextErr = next.ServeHTTP(e)

				// Resolve the error immediately so transport middlewares
				// (like Logger) observe the correct HTTP status code.
				if nextErr != nil && e.errorHandler != nil {
					e.errorHandler(e, nextErr)
					nextErr = nil // Prevent double-handling upstream
				}
			})

			pipe(h).ServeHTTP(e.W, e.R)
			return nextErr
		})
	}
}

// Recover mirrors [middleware.Recover] for use in the router.
func Recover(logger *slog.Logger) Middleware {
	return Adapt(middleware.Recover(logger))
}

// RequestID mirrors [middleware.RequestID] for use in the router.
func RequestID() Middleware {
	return Adapt(middleware.RequestID())
}

// Log mirrors [middleware.Log] for use in the router.
func Log(logger *slog.Logger) Middleware {
	return Adapt(middleware.Log(logger))
}

// Volatile mirrors [middleware.Volatile] for use in the router.
func Volatile() Middleware {
	return Adapt(middleware.Volatile())
}

// Secure mirrors [middleware.Secure] for use in the router.
func Secure(cfg middleware.SecurityConfig) Middleware {
	return Adapt(middleware.Secure(cfg))
}

// CORS mirrors the middleware created by [cors.New] for use in the router.
func CORS(opts ...cors.Option) Middleware {
	return Adapt(cors.New(opts...))
}

// Gzip mirrors the middleware created by [gzip.New] for use in the router.
func Gzip(opts ...gzip.Option) Middleware {
	return Adapt(gzip.New(opts...))
}

// Option defines a functional configuration option for the [Router].
type Option func(*Router)

// WithMiddleware adds global middleware to the [Router].
func WithMiddleware(mws ...Middleware) Option {
	return func(r *Router) {
		r.mws = append(r.mws, mws...)
	}
}

// WithMaxBodySize sets the maximum allowed size for request bodies.
func WithMaxBodySize(bytes int64) Option {
	return func(r *Router) {
		r.maxBytes = bytes
	}
}

// WithJSONOptions sets custom JSON options for the [Router].
func WithJSONOptions(opts ...json.Options) Option {
	return func(r *Router) {
		r.jsonOpts = opts
	}
}

// WithErrorHandler sets a custom error handler.
func WithErrorHandler(h ErrorHandler) Option {
	return func(r *Router) {
		if h != nil {
			r.errorHandler = h
		}
	}
}

// WithLogger updates the default error handler to use the given logger.
func WithLogger(logger *slog.Logger) Option {
	return func(r *Router) {
		if logger != nil {
			r.errorHandler = defaultErrorHandler(logger)
		}
	}
}

// Router represents an HTTP request router with middleware support.
type Router struct {
	// Mux is the underlying standard [*http.ServeMux].
	Mux *http.ServeMux
	// mws is the global slice of middleware.
	mws []Middleware
	// maxBytes is the maximum request body size limit.
	maxBytes int64
	// jsonOpts are the standard JSON options used for I/O.
	jsonOpts []json.Options
	// errorHandler processes errors returned by handlers.
	errorHandler ErrorHandler
}

// New creates a new [Router] instance with the provided options.
func New(opts ...Option) *Router {
	r := &Router{
		Mux:          http.NewServeMux(),
		mws:          nil,
		errorHandler: defaultErrorHandler(slog.Default()),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// ServeHTTP satisfies the [http.Handler] interface.
func (r *Router) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	r.Mux.ServeHTTP(res, req)
}

// Handle registers a new route with a pattern and handler.
//
// The pattern must follow Go 1.22+ syntax. The handler is wrapped with the
// Router's global middleware and any local middleware provided.
func (r *Router) Handle(
	pattern string,
	handler Handler,
	mws ...Middleware,
) {
	local := make([]Middleware, 0, len(r.mws)+len(mws))
	local = append(local, r.mws...)
	local = append(local, mws...)

	chained := Chain(handler, local...)

	h := http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		if r.maxBytes > 0 {
			req.Body = http.MaxBytesReader(res, req.Body, r.maxBytes)
		}

		e := &Exchange{
			R:            req,
			W:            NewResponseWriter(res),
			jsonOpts:     r.jsonOpts,
			errorHandler: r.errorHandler,
		}

		if err := chained.ServeHTTP(e); err != nil {
			r.errorHandler(e, err)
		}
	})

	r.Mux.Handle(pattern, h)
}

// HandleFunc is a convenience wrapper for [Router.Handle].
func (r *Router) HandleFunc(
	pattern string,
	fn func(*Exchange) error,
	mws ...Middleware,
) {
	r.Handle(pattern, HandlerFunc(fn), mws...)
}

// Mount registers a standard [http.Handler] under a pattern.
func (r *Router) Mount(pattern string, handler http.Handler) {
	r.Handle(pattern, Wrap(handler))
}

// defaultErrorHandler centralizes error processing.
func defaultErrorHandler(logger *slog.Logger) ErrorHandler {
	return func(e *Exchange, err error) {
		if e.W.Closed() {
			logger.Error(
				"Handler returned error after writing response",
				slog.Any("err", err),
			)
			return
		}
		ae := &Error{}
		ok := errors.As(err, &ae)
		if !ok {
			id := ErrorID()

			logger.Error(
				"An internal server error occurred",
				slog.String("error_id", id),
				slog.Any("err", err),
			)

			ae = &Error{
				Status:      http.StatusInternalServerError,
				Reason:      ReasonServerError,
				Description: "an unhandled internal error occurred",
				ID:          id,
			}
		}

		if we := e.JSON(ae.Status, ae); we != nil {
			logger.Warn("Failed to write error response", slog.Any("err", we))
		}
	}
}
