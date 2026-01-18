// Package router provides a lightweight, JSON-centric wrapper around Go's
// native http.ServeMux.
//
// It simplifies building JSON APIs by offering a consolidated "Exchange" object
// for handling requests and responses, standardized error formatting, and a
// middleware chaining mechanism.
//
// Basic Usage:
//
//	// 1. Setup the router with options
//	logger := log.New()
//	r := router.New(
//		router.WithLogger(logger),
//		router.WithMiddleware(middleware.Log(logger)),
//	)
//
//	// 2. Define a handler
//	// You can use a closure, or a struct that satisfies the Handler interface.
//	r.HandleFunc("POST /users", func(e *router.Exchange) error {
//		var req CreateUserRequest
//
//		// BindJSON enforces Content-Type and parses the body.
//		// It returns a specific *router.Error type if validation fails.
//		if err := e.BindJSON(&req); err != nil {
//			return err
//		}
//
//		// ... Logic to save user ...
//
//		// Return JSON response
//		return e.JSON(http.StatusCreated, UserResponse{ID: "123"})
//	})
//
//	// 3. Start the server
//	http.ListenAndServe(":8080", r)
package router

import (
	"context"
	"encoding/json/v2"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/middleware"
)

// Standard error reasons used for machine-readable error codes.
const (
	// ReasonWrongType indicates that the request had an unsupported content type.
	ReasonWrongType = "wrong_type"
	// ReasonEmptyBody indicates that the request body was empty.
	ReasonEmptyBody = "empty_body"
	// ReasonParseJSON indicates that there was an error parsing the JSON body.
	ReasonParseJSON = "parse_json"
	// ReasonParseForm indicates that there was an error parsing form data.
	ReasonParseForm = "parse_form"
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

// Error describes the standardized shape of API errors returned to clients.
//
// Handlers can return this struct directly to control the HTTP status code
// and error details. If a handler returns a standard Go error, the Router
// will wrap it in a generic internal server error.
type Error struct {
	// Status is the HTTP status code (e.g., 400, 404, 500).
	Status int `json:"status"`
	// Reason is a short string identifying the error type (e.g.,
	// "invalid_input").
	Reason string `json:"reason"`
	// Description is a human-readable explanation of the error cause.
	Description string `json:"description"`
	// ID is a unique identifier of the specific occurrence for tracing purposes
	// (optional).
	ID string `json:"id,omitempty"`
	// Cause is the underlying error that triggered this error (if any).
	// It is excluded from JSON serialization to prevent leaking internal details.
	Cause error `json:"-"`
}

// Error implements the generic error interface.
func (e *Error) Error() string {
	return e.Reason + ": " + e.Description
}

// Exchange acts as a context object for a single HTTP request/response cycle.
//
// It wraps the underlying *http.Request and http.ResponseWriter to provide
// convenient helper methods for common API tasks, such as parsing JSON,
// reading parameters, and writing structured responses.
type Exchange struct {
	// R is the incoming HTTP request.
	R *http.Request
	// W is a writer for the outgoing HTTP response.
	W http.ResponseWriter
	// jsonOpts is inherited from the parent Router.
	jsonOpts []json.Options
}

// Context returns the request's context.
// This is commonly used for cancellation signals and request scoping.
func (e *Exchange) Context() context.Context { return e.R.Context() }

// Method returns the HTTP method (GET, POST, etc.) of the request.
func (e *Exchange) Method() string { return e.R.Method }

// URL returns the full URL of the request.
func (e *Exchange) URL() *url.URL { return e.R.URL }

// Path returns the URL path of the request.
func (e *Exchange) Path() string { return e.R.URL.Path }

// Param retrieves a path parameter by name.
//
// This relies on the routing pattern (e.g., "GET /users/{id}"). If the
// parameter does not exist, it returns an empty string.
func (e *Exchange) Param(name string) string { return e.R.PathValue(name) }

// Query parses the URL query parameters of the request. Malformed pairs will
// be silently discarded.
func (e *Exchange) Query() url.Values { return e.R.URL.Query() }

// Header returns the HTTP headers of the request.
func (e *Exchange) Header() http.Header { return e.R.Header }

// GetHeader retrieves a specific header value from the request.
func (e *Exchange) GetHeader(key string) string { return e.R.Header.Get(key) }

// SetHeader sets a specific header value in the response.
func (e *Exchange) SetHeader(key, value string) { e.W.Header().Set(key, value) }

// BindJSON decodes the request body into v.
//
// This method enforces strict API hygiene:
// 1. It verifies that the media type is "application/json".
// 2. It checks that the payload is not empty.
// 3. It unmarshals the JSON.
//
// If any of these checks fail, it returns a structured error that handlers
// can return directly.
func (e *Exchange) BindJSON(v any) *Error {
	if t := header.MediaType(e.R.Header); t != MediaTypeJSON {
		return &Error{
			Status:      http.StatusUnsupportedMediaType,
			Reason:      ReasonWrongType,
			Description: "content-type must be " + MediaTypeJSON,
		}
	}
	if e.R.Body == nil || e.R.Body == http.NoBody {
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
	return nil
}

// ReadForm parses the request body as URL-encoded form data and returns the
// values.
//
// Unlike the standard http.Request.FormValue(), this strictly accesses
// the PostForm (body) only, ignoring URL query parameters. This is crucial
// for security protocols like OAuth to prevent query parameter injection.
func (e *Exchange) ReadForm() (url.Values, *Error) {
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

// JSON encodes v as JSON and writes it to the response with the given HTTP
// status code.
//
// It automatically sets the Content-Type header to MediaTypeJSON if it has not
// already been set. When encoding fails, an error is returned.
func (e *Exchange) JSON(code int, v any) error {
	buf, err := json.Marshal(v, e.jsonOpts...)
	if err != nil {
		// The error handler will catch this and map it to a 500 status.
		return err
	}

	if e.W.Header().Get("Content-Type") == "" {
		e.SetHeader("Content-Type", MediaTypeJSON)
	}

	e.Status(code)

	_, err = e.W.Write(buf)
	return err
}

// Form writes the values as URL-encoded form data with the given status code.
//
// It automatically sets the Content-Type header to MediaTypeForm if it has not
// already been set. When encoding fails, an error is returned.
func (e *Exchange) Form(code int, v url.Values) error {
	if e.W.Header().Get("Content-Type") == "" {
		e.SetHeader("Content-Type", MediaTypeForm)
	}
	e.Status(code)
	_, err := e.W.Write([]byte(v.Encode()))
	return err
}

// Status sends a response with the given status code and no body.
// This is commonly used for HTTP 204 (No Content).
func (e *Exchange) Status(code int) {
	e.W.WriteHeader(code)
}

// NoContent sends a HTTP 204 No Content response.
func (e *Exchange) NoContent() {
	e.Status(http.StatusNoContent)
}

// Redirect replies to the request with a redirect to url, which may be a path
// relative to the request path.
//
// Any non-ASCII characters in url will be percent-encoded, but existing percent
// encodings will not be changed. The provided code should be in the 3xx range.
func (e *Exchange) Redirect(url string, code int) error {
	http.Redirect(e.W, e.R, url, code)
	return nil
}

// RedirectTo constructs a URL by merging the base URL with the provided
// query parameters and redirects the client.
//
// This is particularly useful for callbacks.
func (e *Exchange) RedirectTo(base string, params url.Values, code int) error {
	u, err := url.Parse(base)
	if err != nil {
		return &Error{
			Status:      http.StatusInternalServerError,
			Reason:      ReasonServerError,
			Description: "invalid redirect target",
		}
	}

	// Merge existing query params in 'base' with new 'params'
	q := u.Query()
	for k, vs := range params {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	u.RawQuery = q.Encode()

	http.Redirect(e.W, e.R, u.String(), code)
	return nil
}

// Handler defines the interface for HTTP request handlers used by the Router.
//
// This interface allows using struct-based handlers (useful for dependency
// injection) in addition to simple functions.
type Handler interface {
	// ServeHTTP processes an HTTP request encapsulated in the Exchange object.
	ServeHTTP(e *Exchange) error
}

// HandlerFunc defines the function signature for HTTP request handlers.
type HandlerFunc func(e *Exchange) error

// ServeHTTP satisfies the Handler interface, allowing HandlerFunc to be used
// wherever a Handler is expected.
func (f HandlerFunc) ServeHTTP(e *Exchange) error { return f(e) }

// Ensure HandlerFunc implements Handler.
var _ Handler = HandlerFunc(nil)

// Option defines a functional configuration option for the Router.
type Option func(*Router)

// WithLogger sets a custom logger for the Router. If not set, the Router
// defaults to using slog.Default(). A nil value will be ignored.
func WithLogger(log *slog.Logger) Option {
	return func(r *Router) {
		if log != nil {
			r.logger = log
		}
	}
}

// WithMiddleware adds global middleware pipes to the Router.
// These pipes are applied to every route registered with the Router.
func WithMiddleware(pipes ...middleware.Pipe) Option {
	return func(r *Router) {
		r.mws = append(r.mws, pipes...)
	}
}

// WithMaxBodySize sets the maximum allowed size for request bodies.
// Defaults to 0 (unlimited), but typically should be set (e.g., 1MB).
func WithMaxBodySize(bytes int64) Option {
	return func(r *Router) {
		r.maxBytes = bytes
	}
}

// WithJSONOptions sets custom JSON options for the Router.
// They configure both, marshaling and unmarshaling operations.
func WithJSONOptions(opts ...json.Options) Option {
	return func(r *Router) {
		r.jsonOpts = opts
	}
}

// Router represents an HTTP request router with middleware support.
type Router struct {
	// Mux is the underlying http.ServeMux. It is exposed to allow direct
	// usage with http.ListenAndServe.
	Mux      *http.ServeMux
	mws      []middleware.Pipe
	logger   *slog.Logger
	maxBytes int64
	jsonOpts []json.Options
}

// New creates a new Router instance with the provided options.
func New(opts ...Option) *Router {
	r := &Router{
		Mux:    http.NewServeMux(),
		mws:    nil,
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// ServeHTTP satisfies the http.Handler interface, allowing the Router to be
// used directly with HTTP servers. It delegates request handling to the
// underlying http.ServeMux.
func (r *Router) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	r.Mux.ServeHTTP(res, req)
}

// Handle registers a new route with the given pattern, handler, and optional
// middleware pipes.
//
// The pattern string must follow Go 1.22+ syntax (e.g., "GET /users/{id}").
//
// The handler is wrapped with the Router's global middleware and any local
// middleware provided for this specific route.
func (r *Router) Handle(
	pattern string,
	handler Handler,
	mws ...middleware.Pipe,
) {
	h := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		res := &responseWriter{
			ResponseWriter: rw,
			status:         http.StatusOK,
		}

		// Enforce body size limit if configured.
		if r.maxBytes > 0 {
			req.Body = http.MaxBytesReader(rw, req.Body, r.maxBytes)
		}

		e := &Exchange{
			R: req,
			W: res,
		}

		err := handler.ServeHTTP(e)

		if err != nil {
			r.handle(e, res, err)
		}
	})

	// Combine global and local middleware.
	local := append(r.mws, mws...)
	r.Mux.Handle(pattern, middleware.Chain(h, local...))
}

// HandleFunc is a convenience wrapper for Handle that accepts a function
// instead of a Handler interface.
func (r *Router) HandleFunc(
	pattern string,
	fn func(*Exchange) error,
	mws ...middleware.Pipe,
) {
	r.Handle(pattern, HandlerFunc(fn), mws...)
}

// Mount registers a standard http.Handler (like http.FileServer) under a
// pattern.
//
// The handler will still be wrapped by the Router's global middleware,
// ensuring logging/auth logic applies to these routes as well.
func (r *Router) Mount(pattern string, handler http.Handler) {
	r.Mux.Handle(pattern, middleware.Chain(handler, r.mws...))
}

// handle centralizes error processing.
func (r *Router) handle(e *Exchange, rw *responseWriter, err error) {
	// NOTE: This function could be replaced by a customizable error handler
	// in the future.
	if rw.written {
		// Response is already committed; we cannot write a JSON error.
		// Log the error and exit to prevent "superfluous response.WriteHeader".
		r.logger.Error(
			"Handler returned error after writing response",
			slog.Any("err", err),
		)
		return
	}
	ae, ok := err.(*Error)
	if !ok {
		// Log the internal error details for debugging.
		r.logger.Error("An internal server error occurred", slog.Any("err", err))
		ae = &Error{
			Status:      http.StatusInternalServerError,
			Reason:      ReasonServerError,
			Description: "internal server error",
		}
	}

	// Attempt to write the error response.
	// Note: If the handler has already flushed data to the response writer,
	// this may fail or append garbage, but standard HTTP flow stops here.
	if we := e.JSON(ae.Status, ae); we != nil {
		// If writing the error JSON fails (e.g. broken pipe), log it.
		r.logger.Warn("Failed to write error response", slog.Any("err", we))
	}
}

// responseWriter is a wrapper around http.ResponseWriter that tracks
// if the response has already been written to.
type responseWriter struct {
	http.ResponseWriter
	written bool
	status  int
}

// WriteHeader implements http.ResponseWriter interface.
func (rw *responseWriter) WriteHeader(code int) {
	if rw.written {
		return
	}
	rw.status = code
	rw.written = true
	rw.ResponseWriter.WriteHeader(code)
}

// Write implements http.ResponseWriter interface.
func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}
