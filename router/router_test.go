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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockHandler implements router.Handler
type mockHandler struct{}

func (m *mockHandler) ServeHTTP(e *router.Exchange) error {
	e.Status(http.StatusOK)
	return nil
}

func TestExchangeBindJSON(t *testing.T) {
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
			name:       "failure_wrong_content_type",
			ctype:      "text/plain",
			body:       `{}`,
			wantErr:    true,
			wantReason: router.ReasonWrongType,
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:       "failure_empty_body",
			ctype:      "application/json",
			useNilBody: true,
			wantErr:    true,
			wantReason: router.ReasonEmptyBody,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "failure_malformed_json",
			ctype:      "application/json",
			body:       `{"name":`,
			wantErr:    true,
			wantReason: router.ReasonParseJSON,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var r *http.Request
			if tc.useNilBody {
				r = httptest.NewRequest(http.MethodPost, "/", nil)
			} else {
				reader := strings.NewReader(tc.body)
				r = httptest.NewRequest(http.MethodPost, "/", reader)
			}

			if tc.ctype != "" {
				r.Header.Set("Content-Type", tc.ctype)
			}

			e := &router.Exchange{R: r}
			var v map[string]any

			err := e.BindJSON(&v)

			if tc.wantErr {
				require.NotNil(t, err)
				assert.Equal(t, tc.wantReason, err.Reason)
				assert.Equal(t, tc.wantStatus, err.Status)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestExchangeReadForm(t *testing.T) {
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
			name:    "success_basic",
			ctype:   "application/x-www-form-urlencoded",
			body:    "foo=bar&baz=qux",
			wantErr: false,
			wantKey: "foo",
			wantVal: "bar",
		},
		{
			name:        "success_ignore_query_params",
			ctype:       "application/x-www-form-urlencoded",
			body:        "foo=good",
			queryParams: "?foo=bad&evil=true",
			wantErr:     false,
			wantKey:     "foo",
			wantVal:     "good",
			missingKey:  "evil",
		},
		{
			name:       "failure_wrong_content_type",
			ctype:      "application/json",
			body:       `{"foo":"bar"}`,
			wantErr:    true,
			wantReason: router.ReasonWrongType,
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:       "failure_malformed_encoding",
			ctype:      "application/x-www-form-urlencoded",
			body:       "foo=%ZZ",
			wantErr:    true,
			wantReason: router.ReasonParseForm,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(
				http.MethodPost,
				"/"+tc.queryParams,
				strings.NewReader(tc.body),
			)
			if tc.ctype != "" {
				r.Header.Set("Content-Type", tc.ctype)
			}

			e := &router.Exchange{R: r}

			vals, err := e.ReadForm()

			if tc.wantErr {
				require.NotNil(t, err)
				assert.Equal(t, tc.wantReason, err.Reason)
				assert.Equal(t, tc.wantStatus, err.Status)
				assert.Nil(t, vals)
			} else {
				require.Nil(t, err)
				assert.Equal(t, tc.wantVal, vals.Get(tc.wantKey))
				if tc.missingKey != "" {
					v := vals.Get(tc.missingKey)
					assert.Empty(t, v, "should not contain query params")
				}
			}
		})
	}
}

func TestExchangeJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	e := &router.Exchange{W: router.NewResponseWriter(rec)}
	payload := map[string]string{"foo": "bar"}

	err := e.JSON(http.StatusCreated, payload)

	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.JSONEq(t, `{"foo":"bar"}`, rec.Body.String())
}

func TestExchangeForm(t *testing.T) {
	t.Run("write_form_data", func(t *testing.T) {
		rec := httptest.NewRecorder()
		e := &router.Exchange{W: router.NewResponseWriter(rec)}

		vals := url.Values{}
		vals.Set("foo", "bar")
		vals.Set("space", "a b")

		err := e.Form(http.StatusOK, vals)

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		ct := rec.Header().Get("Content-Type")
		assert.Equal(t, "application/x-www-form-urlencoded", ct)
		assert.Equal(t, "foo=bar&space=a+b", rec.Body.String())
	})

	t.Run("write_form_manual_content_type", func(t *testing.T) {
		rec := httptest.NewRecorder()
		e := &router.Exchange{W: router.NewResponseWriter(rec)}

		e.SetHeader("Content-Type", "text/plain")
		vals := url.Values{"a": {"b"}}

		err := e.Form(http.StatusOK, vals)
		require.NoError(t, err)

		ct := rec.Header().Get("Content-Type")
		assert.Equal(t, "text/plain", ct)
	})
}

func TestStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	e := &router.Exchange{W: router.NewResponseWriter(rec)}

	e.Status(http.StatusNoContent)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestExchangeRedirect(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/old", nil)
	e := &router.Exchange{R: req, W: router.NewResponseWriter(rec)}

	err := e.Redirect("/new", http.StatusFound)

	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "/new", rec.Header().Get("Location"))
}

func TestExchangeRedirectTo(t *testing.T) {
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

	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, rec.Code)

	loc, _ := url.Parse(rec.Header().Get("Location"))
	assert.Equal(t, "client.com", loc.Host)
	assert.Equal(t, "/cb", loc.Path)

	q := loc.Query()
	assert.Equal(t, "123", q.Get("code"))
	assert.Equal(t, "xyz", q.Get("state"))
	assert.Equal(t, "2", q.Get("version"))
}

func TestExchangeHelpers(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/users/123?q=search", nil)
	req.SetPathValue("id", "123")
	rec := httptest.NewRecorder()
	e := &router.Exchange{R: req, W: router.NewResponseWriter(rec)}

	assert.Equal(t, http.MethodGet, e.Method())
	assert.Equal(t, "/users/123", e.Path())
	assert.NotNil(t, e.URL())
	assert.NotNil(t, e.Context())
	assert.Equal(t, "123", e.Param("id"))
	assert.Equal(t, "search", e.Query().Get("q"))

	req.Header.Set("X-In", "foo")
	assert.Equal(t, "foo", e.GetHeader("X-In"))

	e.SetHeader("X-Out", "bar")
	assert.Equal(t, "bar", rec.Header().Get("X-Out"))
}

func TestRouterHandle(t *testing.T) {
	r := router.New()

	r.HandleFunc("GET /func", func(e *router.Exchange) error {
		return e.JSON(http.StatusOK, map[string]string{"type": "func"})
	})

	r.Handle("GET /struct", &mockHandler{})

	srv := httptest.NewServer(r)
	defer srv.Close()

	res1, err := http.Get(srv.URL + "/func")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res1.StatusCode)

	res2, err := http.Get(srv.URL + "/struct")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res2.StatusCode)
}

func TestRouterErrorHandling(t *testing.T) {
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

	res1, _ := http.Get(srv.URL + "/typed")
	assert.Equal(t, http.StatusTeapot, res1.StatusCode)

	res2, _ := http.Get(srv.URL + "/std")
	assert.Equal(t, http.StatusInternalServerError, res2.StatusCode)
}

func TestRouterStrictDecoding(t *testing.T) {
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
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestRouterMaxBodySize(t *testing.T) {
	r := router.New(
		router.WithMaxBodySize(10),
	)

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
	require.NoError(t, err)
	assert.True(
		t,
		res.StatusCode == http.StatusBadRequest ||
			res.StatusCode == http.StatusRequestEntityTooLarge,
	)
}

func TestRouterDoubleWrite(t *testing.T) {
	r := router.New()

	r.HandleFunc("GET /double", func(e *router.Exchange) error {
		e.JSON(http.StatusCreated, map[string]string{"ok": "true"})
		return errors.New("late error")
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/double")
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, res.StatusCode)
}

func TestRouterMount(t *testing.T) {
	r := router.New()

	subMux := http.NewServeMux()
	subMux.HandleFunc("/mnt/check", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	r.Mount("/mnt/", subMux)

	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/mnt/check")
	require.NoError(t, err)
	assert.Equal(t, http.StatusAccepted, res.StatusCode)
}

func TestRouterMiddleware(t *testing.T) {
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Global", "true")
			next.ServeHTTP(w, r)
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
	assert.Equal(t, "true", res.Header.Get("X-Global"))
}

func TestResponseWriter_Unwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := router.NewResponseWriter(rec)
	rc := http.NewResponseController(rw)

	err := rc.Flush()
	assert.NoError(t, err, "ResponseController should be able to Flush via Unwrap")
}

func TestError_ErrorString(t *testing.T) {
	e := &router.Error{
		Reason:      "reason",
		Description: "description",
	}
	assert.Equal(t, "reason: description", e.Error())
}

type unmarshalable struct {
	C chan int
}

func TestExchangeJSON_MarshalError(t *testing.T) {
	rec := httptest.NewRecorder()
	e := &router.Exchange{W: router.NewResponseWriter(rec)}
	err := e.JSON(http.StatusOK, unmarshalable{C: make(chan int)})

	assert.Error(t, err)
	assert.Equal(t, 200, rec.Code)
}

func TestExchangeRedirectTo_Error(t *testing.T) {
	rec := httptest.NewRecorder()
	e := &router.Exchange{W: router.NewResponseWriter(rec)}

	err := e.RedirectTo("http://site.com/\nerror", nil, http.StatusFound)

	require.Error(t, err)
	x, ok := err.(*router.Error)
	require.True(t, ok)
	assert.Equal(t, router.ReasonServerError, x.Reason)
}

func TestExchange_NoContent(t *testing.T) {
	rec := httptest.NewRecorder()
	e := &router.Exchange{W: router.NewResponseWriter(rec)}

	e.NoContent()

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.True(t, e.W.Closed())
}
