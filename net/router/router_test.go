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

	"github.com/deep-rent/nexus/net/router"
	"github.com/deep-rent/nexus/dat/valid"
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
		target     any
		wantErr    bool
		wantReason string
		wantStatus int
	}{
		{
			name:    "success",
			ctype:   router.MediaTypeJSON,
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
			ctype:      router.MediaTypeJSON,
			useNilBody: true,
			wantErr:    true,
			wantReason: router.ReasonEmptyBody,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "failure malformed json",
			ctype:      router.MediaTypeJSON,
			body:       `{"name":`,
			wantErr:    true,
			wantReason: router.ReasonParseJSON,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "failure validation",
			ctype:      router.MediaTypeJSON,
			body:       `{"name":""}`,
			target:     &mockValidatable{},
			wantErr:    true,
			wantReason: router.ReasonValidationFailed,
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
			target := tt.target
			if target == nil {
				target = &v
			}

			err := bindJSONAny(e, target)

			if tt.wantErr {
				if err == nil {
					t.Fatal("should have returned an error")
				}
				if got, want := err.Reason, tt.wantReason; got != want {
					t.Errorf("reason: got %q; want %q", got, want)
				}
				if got, want := err.Status, tt.wantStatus; got != want {
					t.Errorf("status code: got %d; want %d", got, want)
				}
				if tt.wantReason == router.ReasonValidationFailed {
					if err.Context == nil {
						t.Fatal("context: got nil; want non-nil")
					}
					verrs, ok := err.Context.(valid.Error)
					if !ok {
						t.Fatalf(
							"context: got %T; want valid.Error",
							err.Context,
						)
					}
					msgs := verrs["name"]
					if len(msgs) == 0 || msgs[0] != "must not be empty" {
						t.Errorf(
							"name messages: got %v; want [\"must not be empty\"]",
							msgs,
						)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("should not have returned an error: %v", err)
			}
		})
	}
}

func TestExchange_BindQuery(t *testing.T) {
	t.Parallel()

	// mockInput is used to test binding

	tests := []struct {
		name       string
		url        string
		target     any
		wantErr    bool
		wantReason string
		wantStatus int
	}{
		{
			name:    "success",
			url:     "/?name=test&ids=1&ids=2",
			target:  &mockInput{},
			wantErr: false,
		},
		{
			name:       "failure parse",
			url:        "/?age=invalid",
			target:     &mockAgeInput{},
			wantErr:    true,
			wantReason: router.ReasonParseQuery,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "failure validation",
			url:        "/?name=",
			target:     &mockValidatable{},
			wantErr:    true,
			wantReason: router.ReasonValidationFailed,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, tt.url, nil)
			e := &router.Exchange{R: r}

			err := bindQueryAny(e, tt.target)

			if tt.wantErr {
				if err == nil {
					t.Fatal("should have returned an error")
				}
				if got, want := err.Reason, tt.wantReason; got != want {
					t.Errorf("reason: got %q; want %q", got, want)
				}
				if got, want := err.Status, tt.wantStatus; got != want {
					t.Errorf("status code: got %d; want %d", got, want)
				}
				return
			}

			if err != nil {
				t.Errorf("should not have returned an error: %v", err)
			}

			if in, ok := tt.target.(*mockInput); ok && !tt.wantErr {
				if in.Name != "test" {
					t.Errorf("name: got %q; want %q", in.Name, "test")
				}
				if len(in.IDs) != 2 || in.IDs[0] != "1" || in.IDs[1] != "2" {
					t.Errorf("ids: got %v; want [1 2]", in.IDs)
				}
			}
		})
	}
}

func TestExchange_BindForm(t *testing.T) {
	t.Parallel()

	// mockInput is used to test binding

	tests := []struct {
		name       string
		ctype      string
		body       string
		target     any
		wantErr    bool
		wantReason string
		wantStatus int
	}{
		{
			name:    "success",
			ctype:   router.MediaTypeForm,
			body:    "name=test",
			target:  &mockInput{},
			wantErr: false,
		},
		{
			name:       "failure content type",
			ctype:      router.MediaTypeJSON,
			body:       `{"name":"test"}`,
			target:     &mockInput{},
			wantErr:    true,
			wantReason: router.ReasonWrongType,
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:       "failure parse",
			ctype:      router.MediaTypeForm,
			body:       "age=invalid",
			target:     &mockAgeInput{},
			wantErr:    true,
			wantReason: router.ReasonParseForm,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "failure validation",
			ctype:      router.MediaTypeForm,
			body:       "name=",
			target:     &mockValidatable{},
			wantErr:    true,
			wantReason: router.ReasonValidationFailed,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := strings.NewReader(tt.body)
			r := httptest.NewRequest(http.MethodPost, "/", body)
			if tt.ctype != "" {
				r.Header.Set("Content-Type", tt.ctype)
			}

			e := &router.Exchange{R: r}
			err := bindFormAny(e, tt.target)

			if tt.wantErr {
				if err == nil {
					t.Fatal("should have returned an error")
				}
				act, ok := errors.AsType[*router.Error](err)
				if !ok {
					t.Fatalf("error type: got %T; want *router.Error", err)
				}
				if got, want := act.Reason, tt.wantReason; got != want {
					t.Errorf("reason: got %q; want %q", got, want)
				}
				if got, want := act.Status, tt.wantStatus; got != want {
					t.Errorf("status code: got %d; want %d", got, want)
				}
				return
			}

			if err != nil {
				t.Errorf("should not have returned an error: %v", err)
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
			ctype:   router.MediaTypeForm,
			body:    "foo=bar&baz=qux",
			wantErr: false,
			wantKey: "foo",
			wantVal: "bar",
		},
		{
			name:        "success ignore query params",
			ctype:       router.MediaTypeForm,
			body:        "foo=good",
			queryParams: "?foo=bad&evil=true",
			wantErr:     false,
			wantKey:     "foo",
			wantVal:     "good",
			missingKey:  "evil",
		},
		{
			name:       "failure wrong content type",
			ctype:      router.MediaTypeJSON,
			body:       `{"foo":"bar"}`,
			wantErr:    true,
			wantReason: router.ReasonWrongType,
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:       "failure malformed encoding",
			ctype:      router.MediaTypeForm,
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
					t.Fatal("should have returned an error")
				}
				re, ok := errors.AsType[*router.Error](err)
				if !ok {
					t.Fatalf("error type: got %T; want *router.Error", err)
				}
				if got, want := re.Reason, tt.wantReason; got != want {
					t.Errorf("reason: got %q; want %q", got, want)
				}
				if got, want := re.Status, tt.wantStatus; got != want {
					t.Errorf("status code: got %d; want %d", got, want)
				}
				if vals != nil {
					t.Errorf("values: got %v; want nil", vals)
				}
				return
			}

			if err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}
			if got, want := vals.Get(tt.wantKey), tt.wantVal; got != want {
				t.Errorf("for key %q: got %q; want %q", tt.wantKey, got, want)
			}
			if tt.missingKey != "" {
				if got := vals.Get(tt.missingKey); got != "" {
					t.Errorf(
						"for key %q: got %q; want empty",
						tt.missingKey,
						got,
					)
				}
			}
		})
	}
}

type mockValidatable struct {
	Name string `json:"name"`
}

func (m *mockValidatable) Validate(v *valid.Validator) {
	if m == nil {
		return
	}
	v.NotEmpty("name", m.Name)
}

var _ valid.Validatable = (*mockValidatable)(nil)

type mockAgeInput struct {
	Age int `form:"age"`
}
type mockInput struct {
	Name string   `form:"name"`
	IDs  []string `form:"ids"`
}

func bindJSONAny(e *router.Exchange, target any) *router.Error {
	switch v := target.(type) {
	case *map[string]any:
		return e.BindJSON(v)
	case *mockValidatable:
		return e.BindJSON(v)
	default:
		panic("unsupported JSON test type")
	}
}

func bindQueryAny(e *router.Exchange, target any) *router.Error {
	switch v := target.(type) {
	case *mockInput:
		return e.BindQuery(v)
	case *mockAgeInput:
		return e.BindQuery(v)
	case *mockValidatable:
		return e.BindQuery(v)
	default:
		panic("unsupported Query test type")
	}
}

func bindFormAny(e *router.Exchange, target any) error {
	switch v := target.(type) {
	case *mockInput:
		return e.BindForm(v)
	case *mockAgeInput:
		return e.BindForm(v)
	case *mockValidatable:
		return e.BindForm(v)
	default:
		panic("unsupported Form test type")
	}
}

func TestExchange_JSON(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	e := &router.Exchange{W: router.NewResponseWriter(rec)}
	payload := map[string]string{"foo": "bar"}

	if err := e.JSON(http.StatusCreated, payload); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if got, want := rec.Code, http.StatusCreated; got != want {
		t.Errorf("status code: got %d; want %d", got, want)
	}
	if got, want := rec.Header().Get("Content-Type"),
		router.MediaTypeJSON; got != want {
		t.Errorf("content type: got %q; want %q", got, want)
	}

	wantBody := `{"foo":"bar"}`
	if got := strings.TrimSpace(rec.Body.String()); got != wantBody {
		t.Errorf("body: got %q; want %q", got, wantBody)
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
			t.Fatalf("should not have returned an error: %v", err)
		}

		if got, want := rec.Code, http.StatusOK; got != want {
			t.Errorf("status code: got %d; want %d", got, want)
		}
		if got, want := rec.Header().Get("Content-Type"),
			router.MediaTypeForm; got != want {
			t.Errorf("content type: got %q; want %q", got, want)
		}

		wantBody := "foo=bar&space=a+b"
		if got := rec.Body.String(); got != wantBody {
			t.Errorf("body: got %q; want %q", got, wantBody)
		}
	})

	t.Run("write form manual content type", func(t *testing.T) {
		t.Parallel()

		rec := httptest.NewRecorder()
		e := &router.Exchange{W: router.NewResponseWriter(rec)}

		e.SetHeader("Content-Type", "text/plain")
		vals := url.Values{"a": {"b"}}

		if err := e.Form(http.StatusOK, vals); err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}

		if got, want := rec.Header().Get("Content-Type"),
			"text/plain"; got != want {
			t.Errorf("content type: got %q; want %q", got, want)
		}
	})
}

func TestExchange_Status(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	e := &router.Exchange{W: router.NewResponseWriter(rec)}

	e.Status(http.StatusNoContent)
	if got, want := rec.Code, http.StatusNoContent; got != want {
		t.Errorf("got %d; want %d", got, want)
	}
}

func TestExchange_Redirect(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/old", nil)
	e := &router.Exchange{R: req, W: router.NewResponseWriter(rec)}

	if err := e.Redirect("/new", http.StatusFound); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if got, want := rec.Code, http.StatusFound; got != want {
		t.Errorf("status code: got %d; want %d", got, want)
	}
	if got, want := rec.Header().Get("Location"), "/new"; got != want {
		t.Errorf("location: got %q; want %q", got, want)
	}
}

func TestExchange_MetadataHelpers(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/users/123?q=search", nil)
	req.SetPathValue("id", "123")
	rec := httptest.NewRecorder()
	e := &router.Exchange{R: req, W: router.NewResponseWriter(rec)}

	if got, want := e.Method(), http.MethodGet; got != want {
		t.Errorf("method: got %q; want %q", got, want)
	}
	if got, want := e.Path(), "/users/123"; got != want {
		t.Errorf("path: got %q; want %q", got, want)
	}
	if e.URL() == nil {
		t.Error("url: got nil; want non-nil")
	}
	if e.Context() == nil {
		t.Error("context: got nil; want non-nil")
	}
	if got, want := e.Param("id"), "123"; got != want {
		t.Errorf("for path param \"id\": got %q; want %q", got, want)
	}
	if got, want := e.Query().Get("q"), "search"; got != want {
		t.Errorf("for query param \"q\": got %q; want %q", got, want)
	}

	req.Header.Set("X-In", "foo")
	if got, want := e.GetHeader("X-In"), "foo"; got != want {
		t.Errorf("for request header \"X-In\": got %q; want %q", got, want)
	}

	e.SetHeader("X-Out", "bar")
	if got, want := rec.Header().Get("X-Out"), "bar"; got != want {
		t.Errorf("for response header \"X-Out\": got %q; want %q", got, want)
	}
}

func TestExchange_Cookies(t *testing.T) {
	t.Parallel()

	t.Run("get cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "test", Value: "val"}) //nolint:gosec
		e := &router.Exchange{R: req}

		c, err := e.Cookie("test")
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if c.Value != "val" {
			t.Errorf("cookie value: got %q; want %q", c.Value, "val")
		}
	})

	t.Run("set cookie", func(t *testing.T) {
		rec := httptest.NewRecorder()
		e := &router.Exchange{W: router.NewResponseWriter(rec)}

		e.SetCookie(&http.Cookie{Name: "out", Value: "gold"}) //nolint:gosec

		got := rec.Header().Get("Set-Cookie")
		if !strings.Contains(got, "out=gold") {
			t.Errorf("got %q; want it to contain %q", got, "out=gold")
		}
	})
}

func TestNewCookie(t *testing.T) {
	t.Parallel()

	c := router.NewCookie("session", "xyz", 3600, http.SameSiteLaxMode)
	if c.Name != "session" {
		t.Errorf("got name %q, want %q", c.Name, "session")
	}
	if c.Value != "xyz" {
		t.Errorf("got value %q, want %q", c.Value, "xyz")
	}
	if c.Path != "/" {
		t.Errorf("got path %q, want %q", c.Path, "/")
	}
	if c.MaxAge != 3600 {
		t.Errorf("got max age %d, want %d", c.MaxAge, 3600)
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("got same-site %v, want %v", c.SameSite, http.SameSiteLaxMode)
	}
	if !c.Secure {
		t.Errorf("got secure %v, want true", c.Secure)
	}
	if !c.HttpOnly {
		t.Errorf("got http-only %v, want true", c.HttpOnly)
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
			t.Fatalf("should not have returned an error: %v", err)
		}
		if got, want := res.StatusCode, http.StatusOK; got != want {
			t.Errorf("status code: got %d; want %d", got, want)
		}
	})

	t.Run("struct handler", func(t *testing.T) {
		res, err := http.Get(srv.URL + "/struct")
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if got, want := res.StatusCode, http.StatusOK; got != want {
			t.Errorf("status code: got %d; want %d", got, want)
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
		res, err := http.Get(srv.URL + "/typed")
		if err != nil {
			t.Fatalf("http get failed: %v", err)
		}
		if got, want := res.StatusCode, http.StatusTeapot; got != want {
			t.Errorf("status code: got %d; want %d", got, want)
		}
	})

	t.Run("standard error", func(t *testing.T) {
		res, err := http.Get(srv.URL + "/std")
		if err != nil {
			t.Fatalf("http get failed: %v", err)
		}
		if got, want := res.StatusCode,
			http.StatusInternalServerError; got != want {
			t.Errorf("status code: got %d; want %d", got, want)
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
	req.Header.Set("Content-Type", router.MediaTypeJSON)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if got, want := res.StatusCode, http.StatusBadRequest; got != want {
		t.Errorf("status code: got %d; want %d", got, want)
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
	req.Header.Set("Content-Type", router.MediaTypeJSON)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if res.StatusCode != http.StatusBadRequest &&
		res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("got status %d; want 400 or 413", res.StatusCode)
	}
}

func TestRouter_ErrorAfterResponse(t *testing.T) {
	t.Parallel()

	r := router.New()
	r.HandleFunc("GET /double", func(e *router.Exchange) error {
		payload := map[string]string{"ok": "true"}
		if err := e.JSON(http.StatusCreated, payload); err != nil {
			t.Fatalf(
				"writing the response: should not have returned an error: %v",
				err,
			)
		}
		return errors.New("late error")
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/double")
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if got, want := res.StatusCode, http.StatusCreated; got != want {
		t.Errorf("status code: got %d; want %d", got, want)
	}
}

func TestRouter_MountMux(t *testing.T) {
	t.Parallel()

	r := router.New()
	subMux := http.NewServeMux()
	subMux.HandleFunc(
		"/mnt/check",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
		},
	)

	r.Mount("/mnt/", subMux)

	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/mnt/check")
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if got, want := res.StatusCode, http.StatusAccepted; got != want {
		t.Errorf("status code: got %d; want %d", got, want)
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
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestResponseWriter_UnwrapStd(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rw := router.NewResponseWriter(rec)
	rc := http.NewResponseController(rw)

	if err := rc.Flush(); err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}
}

func TestError_ErrorString(t *testing.T) {
	t.Parallel()

	e := &router.Error{
		Reason:      "reason",
		Description: "description",
	}
	if got, want := e.Error(), "reason: description"; got != want {
		t.Errorf("got %q; want %q", got, want)
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
		t.Error("should have returned an error")
	}
}

func TestExchange_NoContent(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	e := &router.Exchange{W: router.NewResponseWriter(rec)}

	e.NoContent()

	if got, want := rec.Code, http.StatusNoContent; got != want {
		t.Errorf("status code: got %d; want %d", got, want)
	}
	if !e.W.Closed() {
		t.Error("closed flag: got false; want true")
	}
}

func TestErrorID(t *testing.T) {
	id := router.ErrorID()

	if id == "" {
		t.Error("got an empty string; want non-empty")
	}

	if id == router.ErrorID() {
		t.Error("got the same ID twice; want unique IDs")
	}
}

func TestRouter_NotFound(t *testing.T) {
	t.Parallel()
	r := router.New()
	req := httptest.NewRequest(http.MethodGet, "/does-not-exist", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}

	var errRes router.Error
	if err := json.Unmarshal(w.Body.Bytes(), &errRes); err != nil {
		t.Fatalf("failed to unmarshal error response: %v", err)
	}

	if errRes.Reason != router.ReasonNotFound {
		t.Errorf(
			"expected reason %q, got %q",
			router.ReasonNotFound,
			errRes.Reason,
		)
	}
}
