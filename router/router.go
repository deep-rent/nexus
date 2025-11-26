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

func (e *Exchange) Context() context.Context { return e.R.Context() }

func (e *Exchange) Method() string { return e.R.Method }

func (e *Exchange) URL() *url.URL { return e.R.URL }

func (e *Exchange) Header() http.Header { return e.R.Header }

func (e *Exchange) Path() string { return e.R.URL.Path }

func (e *Exchange) Param(name string) string { return e.R.PathValue(name) }

func (e *Exchange) Query() url.Values { return e.R.URL.Query() }

func (e *Exchange) SetHeader(key, value string) { e.W.Header().Set(key, value) }

func (e *Exchange) BindJSON(v any) error {
	ct := e.R.Header.Get("Content-Type")
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

func (e *Exchange) JSON(status int, v any) error {
	e.SetHeader("Content-Type", "application/json")
	e.W.WriteHeader(status)
	if err := json.MarshalWrite(e.W, v); err != nil {
		return err
	}
	return nil
}

type Handler func(e *Exchange) error

type Option func(*Router)

func WithLogger(log *slog.Logger) Option {
	return func(r *Router) {
		if log != nil {
			r.logger = log
		}
	}
}

func WithMiddleware(pipes ...middleware.Pipe) Option {
	return func(r *Router) {
		r.global = append(r.global, pipes...)
	}
}

type Router struct {
	Mux    *http.ServeMux
	global []middleware.Pipe
	logger *slog.Logger
}

func New(opts ...Option) *Router {
	r := &Router{
		Mux:    http.NewServeMux(),
		global: nil,
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

func (r *Router) Handle(
	pattern string,
	handler Handler,
	pipes ...middleware.Pipe,
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

	local := append(r.global, pipes...)
	r.Mux.Handle(pattern, middleware.Chain(h, local...))
}

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
