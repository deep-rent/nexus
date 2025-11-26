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

// Error describes the standard shape of API errors.
//
// Any error returned by a handler that is not already of this type will be
// treated as an internal server error.
type Error struct {
	// Status is the HTTP status code.
	Status int `json:"status"`
	// Reason is a short string identifying the error type.
	Reason string `json:"reason"`
	// Description is a human-readable explanation of the error cause.
	Description string `json:"description"`
	// ID is a unique identifier of the specific occurrence for tracing purposes.
	ID string `json:"id,omitempty"`
	// Cause is the underlying error that triggered this error (if any).
	Cause error `json:"-"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	return e.Description
}

type Exchange struct {
	R *http.Request
	W http.ResponseWriter
}

// Context returns the request's context.
func (e *Exchange) Context() context.Context { return e.R.Context() }

// Method returns the HTTP method of the request. An empty string means GET.
func (e *Exchange) Method() string { return e.R.Method }

// URL returns the full URL of the request.
func (e *Exchange) URL() *url.URL { return e.R.URL }

// Path returns the URL path of the request.
func (e *Exchange) Path() string { return e.R.URL.Path }

// Param retrieves a path parameter by name.
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
// If the Content-Type is not application/json, or if the body is empty or
// malformed, an appropriate API error is returned.
func (e *Exchange) BindJSON(v any) error {
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
// status code. If encoding fails, an error is returned.
func (e *Exchange) JSON(status int, v any) error {
	e.SetHeader("Content-Type", "application/json")
	e.W.WriteHeader(status)
	if err := json.MarshalWrite(e.W, v); err != nil {
		return err
	}
	return nil
}

// Handler defines the function signature for HTTP request handlers.
type Handler func(e *Exchange) error

// Option defines a configuration option for the Router.
type Option func(*Router)

// WithLogger sets a custom logger for the Router. If not set, the Router
// defaults to slog.Default(). A nil value will be ignored.
func WithLogger(log *slog.Logger) Option {
	return func(r *Router) {
		if log != nil {
			r.logger = log
		}
	}
}

// WithMiddleware adds global middleware pipes that will be applied to all
// routes registered on the Router.
func WithMiddleware(pipes ...middleware.Pipe) Option {
	return func(r *Router) {
		r.mws = append(r.mws, pipes...)
	}
}

// Router represents an HTTP request router with middleware support.
type Router struct {
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

// Handle registers a new route with the given pattern, handler, and optional
// middleware pipes.
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

		err := handler(e)

		if err != nil {
			r.handle(e, err)
		}
	})

	local := append(r.mws, mws...)
	r.Mux.Handle(pattern, middleware.Chain(h, local...))
}

// handle processes an error returned by a handler and sends an appropriate
// response to the client.
func (r *Router) handle(e *Exchange, err error) {
	ae, ok := err.(*Error)
	if !ok {
		r.logger.Error("An internal server error occurred", slog.Any("err", err))
		ae = &Error{
			Status:      http.StatusInternalServerError,
			Reason:      ReasonServerError,
			Description: "internal server error",
		}
	}

	// If the handler already wrote partial bytes, this may fail.
	_ = e.JSON(ae.Status, ae)
}
