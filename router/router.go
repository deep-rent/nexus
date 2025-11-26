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
//	r.Handle("POST /users", router.HandlerFunc(func(e *router.Exchange) error {
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
//	}))
//
//	// 3. Start the server (Router satisfies http.Handler)
//	http.ListenAndServe(":8080", r)
package router

import (
	"context"
	"encoding/json/v2"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

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
	// ReasonServerError indicates that an unexpected internal error occurred.
	ReasonServerError = "server_error"
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
	return e.Description
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
// 1. It verifies the Content-Type header starts with "application/json".
// 2. It checks that the body is not empty.
// 3. It unmarshals the JSON.
//
// If any of these checks fail, it returns a structured error that handlers
// can return directly.
func (e *Exchange) BindJSON(v any) *Error {
	ct := e.GetHeader("Content-Type")
	if ct != "" && !strings.HasPrefix(ct, "application/json") {
		return &Error{
			Status:      http.StatusUnsupportedMediaType,
			Reason:      ReasonWrongType,
			Description: "wrong content type",
		}
	}
	if e.R.Body == nil {
		return &Error{
			Status:      http.StatusBadRequest,
			Reason:      ReasonEmptyBody,
			Description: "empty request body",
		}
	}
	if err := json.UnmarshalRead(e.R.Body, v); err != nil {
		return &Error{
			Status:      http.StatusBadRequest,
			Reason:      ReasonParseJSON,
			Description: "could not parse JSON body",
		}
	}
	return nil
}

// JSON encodes v as JSON and writes it to the response with the given HTTP
// status code.
//
// It automatically sets the "Content-Type: application/json" header. If
// encoding fails, an error is returned.
func (e *Exchange) JSON(status int, v any) error {
	e.SetHeader("Content-Type", "application/json")
	e.W.WriteHeader(status)
	if err := json.MarshalWrite(e.W, v); err != nil {
		return err
	}
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

// Router represents an HTTP request router with middleware support.
type Router struct {
	// Mux is the underlying http.ServeMux. It is exposed to allow direct
	// usage with http.ListenAndServe.
	Mux    *http.ServeMux
	mws    []middleware.Pipe
	logger *slog.Logger
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
	h := http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		e := &Exchange{
			R: req,
			W: res,
		}

		err := handler.ServeHTTP(e)

		if err != nil {
			r.handle(e, err)
		}
	})

	local := append(r.mws, mws...)
	r.Mux.Handle(pattern, middleware.Chain(h, local...))
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
func (r *Router) handle(e *Exchange, err error) {
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
	if w := e.JSON(ae.Status, ae); w != nil {
		// If writing the error JSON fails (e.g. broken pipe), log it.
		r.logger.Warn("Failed to write error response", slog.Any("err", w))
	}
}
