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
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/nexus/middleware"
	"github.com/deep-rent/nexus/router"
)

type mockHandler struct{}

func (m *mockHandler) ServeHTTP(e *router.Exchange) error {
	e.Status(http.StatusOK)
	return nil
}

var _ router.Handler = (*mockHandler)(nil)

func TestExchange_BindJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		ctype      string
		body       string
		useNilBody bool
		wantErr    bool
		wantReason string
		wantStatus int
	}{
		{
			name:    "success",
			ctype:   "application/json",
			body:    `{"name":"test"}`,
			wantErr: false,
		},
		{
			name:       "failure wrong content type",
			ctype:      "text/plain",
			body:       `{}`,
			wantErr:    true,
			wantReason: router.ReasonWrongType,
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:       "failure empty body",
			ctype:      "application/json",
			useNilBody: true,
			wantErr:    true,
			wantReason: router.ReasonEmptyBody,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "failure malformed json",
			ctype:      "application/json",
			body:       `{"name":`,
			wantErr:    true,
			wantReason: router.ReasonParseJSON,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var body io.Reader
			if tt.useNilBody {
				body = nil
			} else {
				body = strings.NewReader(tt.body)
			}

			r := httptest.NewRequest(http.MethodPost, "/", body)

			if tt.ctype != "" {
				r.Header.Set("Content-Type", tt.ctype)
			}

			e := &router.Exchange{R: r}
			var v map[string]any

			err := e.BindJSON(&v)

			if tt.wantErr {
				if err == nil {
					t.Fatal("BindJSON() err = nil; want non-nil")
				}
				if got, want := err.Reason, tt.wantReason; got != want {
					t.Errorf("err.Reason = %q; want %q", got, want)
				}
				if got, want := err.Status, tt.wantStatus; got != want {
					t.Errorf("err.Status = %d; want %d", got, want)
				}
				return
			}

			if err != nil {
				t.Errorf("BindJSON() err = %v; want nil", err)
			}
		})
	}
}

func TestExchange_ReadForm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		ctype       string
		body        string
		queryParams string
		wantErr     bool
		wantReason  string
		wantStatus  int
		wantKey     string
		wantVal     string
		missingKey  string
	}{
		{
			name:    "success basic",
			ctype:   "application/x-www-form-urlencoded",
			body:    "foo=bar&baz=qux",
			wantErr: false,
			wantKey: "foo",
			wantVal: "bar",
		},
		{
			name:        "success ignore query params",
			ctype:       "application/x-www-form-urlencoded",
			body:        "foo=good",
			queryParams: "?foo=bad&evil=true",
			wantErr:     false,
			wantKey:     "foo",
			wantVal:     "good",
			missingKey:  "evil",
		},
		{
			name:       "failure wrong content type",
			ctype:      "application/json",
			body:       `{"foo":"bar"}`,
			wantErr:    true,
			wantReason: router.ReasonWrongType,
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:       "failure malformed encoding",
			ctype:      "application/x-www-form-urlencoded",
			body:       "foo=%ZZ",
			wantErr:    true,
			wantReason: router.ReasonParseForm,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(
				http.MethodPost,
				"/"+tt.queryParams,
				strings.NewReader(tt.body),
			)
			if tt.ctype != "" {
				r.Header.Set("Content-Type", tt.ctype)
			}

			e := &router.Exchange{R: r}
			vals, err := e.ReadForm()

			if tt.wantErr {
				if err == nil {
					t.Fatal("ReadForm() err = nil; want non-nil")
				}
				if got, want := err.Reason, tt.wantReason; got != want {
					t.Errorf("err.Reason = %q; want %q", got, want)
				}
				if got, want := err.Status, tt.wantStatus; got != want {
					t.Errorf("err.Status = %d; want %d", got, want)
				}
				if vals != nil {
					t.Errorf("ReadForm() vals = %v; want nil", vals)
				}
				return
			}

			if err != nil {
				t.Fatalf("ReadForm() err = %v; want nil", err)
			}
			if got, want := vals.Get(tt.wantKey), tt.wantVal; got != want {
				t.Errorf("vals.Get(%q) = %q; want %q", tt.wantKey, got, want)
			}
			if tt.missingKey != "" {
				if got := vals.Get(tt.missingKey); got != "" {
					t.Errorf("vals.Get(%q) = %q; want empty", tt.missingKey, got)
				}
			}
		})
	}
}

func TestExchange_JSON(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	e := &router.Exchange{W: router.NewResponseWriter(rec)}
	payload := map[string]string{"foo": "bar"}

	if err := e.JSON(http.StatusCreated, payload); err != nil {
		t.Fatalf("JSON() err = %v; want nil", err)
	}

	if got, want := rec.Code, http.StatusCreated; got != want {
		t.Errorf("rec.Code = %d; want %d", got, want)
	}
	if got, want := rec.Header().Get("Content-Type"),
		"application/json"; got != want {
		t.Errorf("Content-Type = %q; want %q", got, want)
	}

	wantBody := `{"foo":"bar"}`
	if got := strings.TrimSpace(rec.Body.String()); got != wantBody {
		t.Errorf("rec.Body = %q; want %q", got, wantBody)
	}
}

func TestExchange_Form(t *testing.T) {
	t.Parallel()

	t.Run("write form data", func(t *testing.T) {
		t.Parallel()

		rec := httptest.NewRecorder()
		e := &router.Exchange{W: router.NewResponseWriter(rec)}

		vals := url.Values{}
		vals.Set("foo", "bar")
		vals.Set("space", "a b")

		if err := e.Form(http.StatusOK, vals); err != nil {
			t.Fatalf("Form() err = %v; want nil", err)
		}

		if got, want := rec.Code, http.StatusOK; got != want {
			t.Errorf("rec.Code = %d; want %d", got, want)
		}
		if got, want := rec.Header().Get("Content-Type"),
			"application/x-www-form-urlencoded"; got != want {
			t.Errorf("Content-Type = %q; want %q", got, want)
		}

		wantBody := "foo=bar&space=a+b"
		if got := rec.Body.String(); got != wantBody {
			t.Errorf("rec.Body = %q; want %q", got, wantBody)
		}
	})

	t.Run("write form manual content type", func(t *testing.T) {
		t.Parallel()

		rec := httptest.NewRecorder()
		e := &router.Exchange{W: router.NewResponseWriter(rec)}

		e.SetHeader("Content-Type", "text/plain")
		vals := url.Values{"a": {"b"}}

		if err := e.Form(http.StatusOK, vals); err != nil {
			t.Fatalf("Form() err = %v; want nil", err)
		}

		if got, want := rec.Header().Get("Content-Type"),
			"text/plain"; got != want {
			t.Errorf("Content-Type = %q; want %q", got, want)
		}
	})
}

func TestExchange_Status(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	e := &router.Exchange{W: router.NewResponseWriter(rec)}

	e.Status(http.StatusNoContent)
	if got, want := rec.Code, http.StatusNoContent; got != want {
		t.Errorf("rec.Code = %d; want %d", got, want)
	}
}

func TestExchange_Redirect(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/old", nil)
	e := &router.Exchange{R: req, W: router.NewResponseWriter(rec)}

	if err := e.Redirect("/new", http.StatusFound); err != nil {
		t.Fatalf("Redirect() err = %v; want nil", err)
	}

	if got, want := rec.Code, http.StatusFound; got != want {
		t.Errorf("rec.Code = %d; want %d", got, want)
	}
	if got, want := rec.Header().Get("Location"), "/new"; got != want {
		t.Errorf("Location = %q; want %q", got, want)
	}
}

func TestExchange_RedirectTo(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	e := &router.Exchange{R: req, W: router.NewResponseWriter(rec)}

	params := url.Values{}
	params.Set("code", "123")
	params.Set("state", "xyz")

	err := e.RedirectTo(
		"https://client.com/cb?version=2",
		params,
		http.StatusFound,
	)
	if err != nil {
		t.Fatalf("RedirectTo() err = %v; want nil", err)
	}

	if got, want := rec.Code, http.StatusFound; got != want {
		t.Errorf("rec.Code = %d; want %d", got, want)
	}

	loc, _ := url.Parse(rec.Header().Get("Location"))
	if got, want := loc.Host, "client.com"; got != want {
		t.Errorf("loc.Host = %q; want %q", got, want)
	}
	if got, want := loc.Path, "/cb"; got != want {
		t.Errorf("loc.Path = %q; want %q", got, want)
	}

	q := loc.Query()
	if got, want := q.Get("code"), "123"; got != want {
		t.Errorf("query.code = %q; want %q", got, want)
	}
	if got, want := q.Get("state"), "xyz"; got != want {
		t.Errorf("query.state = %q; want %q", got, want)
	}
	if got, want := q.Get("version"), "2"; got != want {
		t.Errorf("query.version = %q; want %q", got, want)
	}
}

func TestExchange_MetadataHelpers(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/users/123?q=search", nil)
	req.SetPathValue("id", "123")
	rec := httptest.NewRecorder()
	e := &router.Exchange{R: req, W: router.NewResponseWriter(rec)}

	if got, want := e.Method(), http.MethodGet; got != want {
		t.Errorf("Method() = %q; want %q", got, want)
	}
	if got, want := e.Path(), "/users/123"; got != want {
		t.Errorf("Path() = %q; want %q", got, want)
	}
	if e.URL() == nil {
		t.Error("URL() = nil; want non-nil")
	}
	if e.Context() == nil {
		t.Error("Context() = nil; want non-nil")
	}
	if got, want := e.Param("id"), "123"; got != want {
		t.Errorf("Param(\"id\") = %q; want %q", got, want)
	}
	if got, want := e.Query().Get("q"), "search"; got != want {
		t.Errorf("Query().Get(\"q\") = %q; want %q", got, want)
	}

	req.Header.Set("X-In", "foo")
	if got, want := e.GetHeader("X-In"), "foo"; got != want {
		t.Errorf("GetHeader(\"X-In\") = %q; want %q", got, want)
	}

	e.SetHeader("X-Out", "bar")
	if got, want := rec.Header().Get("X-Out"), "bar"; got != want {
		t.Errorf("Header.Get(\"X-Out\") = %q; want %q", got, want)
	}
}

func TestRouter_RouteMatching(t *testing.T) {
	t.Parallel()

	r := router.New()
	r.HandleFunc("GET /func", func(e *router.Exchange) error {
		return e.JSON(http.StatusOK, map[string]string{"type": "func"})
	})
	r.Handle("GET /struct", &mockHandler{})

	srv := httptest.NewServer(r)
	defer srv.Close()

	t.Run("func handler", func(t *testing.T) {
		res, err := http.Get(srv.URL + "/func")
		if err != nil {
			t.Fatalf("http.Get() err = %v", err)
		}
		if got, want := res.StatusCode, http.StatusOK; got != want {
			t.Errorf("res.StatusCode = %d; want %d", got, want)
		}
	})

	t.Run("struct handler", func(t *testing.T) {
		res, err := http.Get(srv.URL + "/struct")
		if err != nil {
			t.Fatalf("http.Get() err = %v", err)
		}
		if got, want := res.StatusCode, http.StatusOK; got != want {
			t.Errorf("res.StatusCode = %d; want %d", got, want)
		}
	})
}

func TestRouter_ErrorResponse(t *testing.T) {
	t.Parallel()

	r := router.New()
	r.HandleFunc("GET /typed", func(e *router.Exchange) error {
		return &router.Error{
			Status:  http.StatusTeapot,
			Reason:  "tea_time",
			Context: map[string]any{"brand": "earl_grey"},
		}
	})
	r.HandleFunc("GET /std", func(e *router.Exchange) error {
		return errors.New("db crash")
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	t.Run("typed error", func(t *testing.T) {
		res, _ := http.Get(srv.URL + "/typed")
		if got, want := res.StatusCode, http.StatusTeapot; got != want {
			t.Errorf("res.StatusCode = %d; want %d", got, want)
		}
	})

	t.Run("standard error", func(t *testing.T) {
		res, _ := http.Get(srv.URL + "/std")
		if got, want := res.StatusCode,
			http.StatusInternalServerError; got != want {
			t.Errorf("res.StatusCode = %d; want %d", got, want)
		}
	})
}

func TestRouter_StrictJSONDecoding(t *testing.T) {
	t.Parallel()

	r := router.New(
		router.WithJSONOptions(json.RejectUnknownMembers(true)),
	)

	type Request struct {
		Name string `json:"name"`
	}

	r.HandleFunc("POST /strict", func(e *router.Exchange) error {
		var req Request
		if err := e.BindJSON(&req); err != nil {
			return err
		}
		e.Status(http.StatusOK)
		return nil
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	body := strings.NewReader(`{"name": "Alice", "age": 30}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/strict", body)
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http.Do() err = %v", err)
	}
	if got, want := res.StatusCode, http.StatusBadRequest; got != want {
		t.Errorf("res.StatusCode = %d; want %d", got, want)
	}
}

func TestRouter_MaxBodyLimit(t *testing.T) {
	t.Parallel()

	r := router.New(router.WithMaxBodySize(10))
	r.HandleFunc("POST /limit", func(e *router.Exchange) error {
		var v map[string]any
		return e.BindJSON(&v)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	body := strings.NewReader(`{"a":"large payload"}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/limit", body)
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http.Do() err = %v", err)
	}

	if res.StatusCode != http.StatusBadRequest &&
		res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("res.StatusCode = %d; want 400 or 413", res.StatusCode)
	}
}

func TestRouter_ErrorAfterResponse(t *testing.T) {
	t.Parallel()

	r := router.New()
	r.HandleFunc("GET /double", func(e *router.Exchange) error {
		payload := map[string]string{"ok": "true"}
		if err := e.JSON(http.StatusCreated, payload); err != nil {
			t.Fatalf("JSON() err = %v", err)
		}
		return errors.New("late error")
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/double")
	if err != nil {
		t.Fatalf("http.Get() err = %v", err)
	}
	if got, want := res.StatusCode, http.StatusCreated; got != want {
		t.Errorf("res.StatusCode = %d; want %d", got, want)
	}
}

func TestRouter_MountMux(t *testing.T) {
	t.Parallel()

	r := router.New()
	subMux := http.NewServeMux()
	subMux.HandleFunc("/mnt/check", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	r.Mount("/mnt/", subMux)

	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/mnt/check")
	if err != nil {
		t.Fatalf("http.Get() err = %v", err)
	}
	if got, want := res.StatusCode, http.StatusAccepted; got != want {
		t.Errorf("res.StatusCode = %d; want %d", got, want)
	}
}

func TestRouter_MiddlewareHeader(t *testing.T) {
	t.Parallel()

	mw := func(next router.Handler) router.Handler {
		return router.HandlerFunc(func(e *router.Exchange) error {
			e.SetHeader("X-Global", "true")
			return next.ServeHTTP(e)
		})
	}

	r := router.New(router.WithMiddleware(mw))
	r.HandleFunc("GET /", func(e *router.Exchange) error {
		e.Status(http.StatusOK)
		return nil
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	res, _ := http.Get(srv.URL + "/")
	if got, want := res.Header.Get("X-Global"), "true"; got != want {
		t.Errorf("X-Global = %q; want %q", got, want)
	}
}

func TestHandler_ChainMiddleware(t *testing.T) {
	t.Parallel()

	appendHeader := func(val string) router.Middleware {
		return func(next router.Handler) router.Handler {
			return router.HandlerFunc(func(e *router.Exchange) error {
				current := e.W.Header().Get("X-Chain")
				e.SetHeader("X-Chain", current+val)
				return next.ServeHTTP(e)
			})
		}
	}

	h := router.Chain(
		router.HandlerFunc(func(e *router.Exchange) error {
			current := e.W.Header().Get("X-Chain")
			e.SetHeader("X-Chain", current+"C")
			return nil
		}),
		appendHeader("A"),
		appendHeader("B"),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	e := &router.Exchange{R: req, W: router.NewResponseWriter(rec)}

	if err := h.ServeHTTP(e); err != nil {
		t.Fatalf("ServeHTTP() err = %v", err)
	}
	if got, want := rec.Header().Get("X-Chain"), "ABC"; got != want {
		t.Errorf("X-Chain = %q; want %q", got, want)
	}
}

func TestHandler_WrapStd(t *testing.T) {
	t.Parallel()

	stdHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Wrapped", "true")
		w.WriteHeader(http.StatusAccepted)
	})

	r := router.New()
	r.Handle("GET /wrap", router.Wrap(stdHandler))

	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/wrap")
	if err != nil {
		t.Fatalf("http.Get() err = %v", err)
	}
	if got, want := res.StatusCode, http.StatusAccepted; got != want {
		t.Errorf("res.StatusCode = %d; want %d", got, want)
	}
	if got, want := res.Header.Get("X-Wrapped"), "true"; got != want {
		t.Errorf("X-Wrapped = %q; want %q", got, want)
	}
}

func TestHandler_AdaptStdMiddleware(t *testing.T) {
	t.Parallel()

	var capturedStatus int
	pipe := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			if rw, ok := w.(router.ResponseWriter); ok {
				capturedStatus = rw.Status()
			}
		})
	}

	r := router.New(router.WithMiddleware(router.Adapt(pipe)))
	r.HandleFunc("GET /adapt", func(e *router.Exchange) error {
		return errors.New("boom")
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/adapt")
	if err != nil {
		t.Fatalf("http.Get() err = %v", err)
	}
	if got, want := res.StatusCode, http.StatusInternalServerError; got != want {
		t.Errorf("res.StatusCode = %d; want %d", got, want)
	}
	if got, want := capturedStatus, http.StatusInternalServerError; got != want {
		t.Errorf("capturedStatus = %d; want %d", got, want)
	}
}

func TestResponseWriter_UnwrapStd(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rw := router.NewResponseWriter(rec)
	rc := http.NewResponseController(rw)

	if err := rc.Flush(); err != nil {
		t.Errorf("rc.Flush() err = %v; want nil", err)
	}
}

func TestError_ErrorString(t *testing.T) {
	t.Parallel()

	e := &router.Error{
		Reason:      "reason",
		Description: "description",
	}
	if got, want := e.Error(), "reason: description"; got != want {
		t.Errorf("Error() = %q; want %q", got, want)
	}
}

type mockUnmarshalable struct {
	C chan int
}

func TestExchange_JSONMarshalError(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	e := &router.Exchange{W: router.NewResponseWriter(rec)}
	err := e.JSON(http.StatusOK, mockUnmarshalable{C: make(chan int)})

	if err == nil {
		t.Error("JSON() err = nil; want non-nil for unmarshalable type")
	}
}

func TestExchange_RedirectToError(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	e := &router.Exchange{W: router.NewResponseWriter(rec)}

	err := e.RedirectTo("http://site.com/\nerror", nil, http.StatusFound)

	if err == nil {
		t.Fatal("RedirectTo() err = nil; want non-nil for invalid URL")
	}

	var x *router.Error
	if !errors.As(err, &x) {
		t.Fatalf("err is %T; want *router.Error", err)
	}
	if got, want := x.Reason, router.ReasonServerError; got != want {
		t.Errorf("x.Reason = %q; want %q", got, want)
	}
}

func TestExchange_NoContent(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	e := &router.Exchange{W: router.NewResponseWriter(rec)}

	e.NoContent()

	if got, want := rec.Code, http.StatusNoContent; got != want {
		t.Errorf("rec.Code = %d; want %d", got, want)
	}
	if !e.W.Closed() {
		t.Error("e.W.Closed() = false; want true")
	}
}

func TestMiddleware_Connectivity(t *testing.T) {
	t.Parallel()

	logger := log.Silent()
	tests := []struct {
		name string
		fn   any
	}{
		{"Recover", router.Recover(logger)},
		{"RequestID", router.RequestID()},
		{"Log", router.Log(logger)},
		{"Volatile", router.Volatile()},
		{"Secure", router.Secure(middleware.DefaultSecurityConfig)},
		{"CORS", router.CORS()},
		{"Gzip", router.Gzip()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.fn == nil {
				t.Fatalf("%s middleware factory returned nil", tt.name)
			}
			if _, ok := tt.fn.(router.Middleware); !ok {
				t.Errorf("%s does not satisfy router.Middleware", tt.name)
			}
		})
	}
}
