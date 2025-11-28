package router_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockHandler struct{}

func (m *mockHandler) ServeHTTP(e *router.Exchange) error {
	e.Status(http.StatusOK)
	return nil
}

func TestExchange_BindJSON(t *testing.T) {
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r *http.Request
			if tt.useNilBody {
				r = httptest.NewRequest(http.MethodPost, "/", nil)
			} else {
				r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			}

			if tt.ctype != "" {
				r.Header.Set("Content-Type", tt.ctype)
			}

			e := &router.Exchange{R: r}
			var v map[string]any

			err := e.BindJSON(&v)

			if tt.wantErr {
				require.NotNil(t, err)
				assert.Equal(t, tt.wantReason, err.Reason)
				assert.Equal(t, tt.wantStatus, err.Status)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestExchange_JSON(t *testing.T) {
	rec := httptest.NewRecorder()
	e := &router.Exchange{W: rec}
	payload := map[string]string{"foo": "bar"}

	err := e.JSON(http.StatusCreated, payload)

	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.JSONEq(t, `{"foo":"bar"}`, rec.Body.String())
}

func TestExchange_Status(t *testing.T) {
	rec := httptest.NewRecorder()
	e := &router.Exchange{W: rec}

	e.Status(http.StatusNoContent)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestExchange_Redirect(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/old", nil)
	e := &router.Exchange{R: req, W: rec}

	err := e.Redirect("/new", http.StatusFound)

	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "/new", rec.Header().Get("Location"))
}

func TestExchange_Helpers(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/users/123?q=search", nil)
	req.SetPathValue("id", "123")
	rec := httptest.NewRecorder()
	e := &router.Exchange{R: req, W: rec}

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

func TestRouter_Handle(t *testing.T) {
	r := router.New()

	r.HandleFunc("GET /func", func(e *router.Exchange) error {
		return e.JSON(http.StatusOK, map[string]string{"type": "func"})
	})

	r.Handle("GET /struct", &mockHandler{})

	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/func")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp2, err := http.Get(srv.URL + "/struct")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

func TestRouter_ErrorHandling(t *testing.T) {
	r := router.New()

	r.HandleFunc("GET /typed", func(e *router.Exchange) error {
		return &router.Error{
			Status: http.StatusTeapot,
			Reason: "tea_time",
		}
	})

	r.HandleFunc("GET /std", func(e *router.Exchange) error {
		return errors.New("db crash")
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	resp1, _ := http.Get(srv.URL + "/typed")
	assert.Equal(t, http.StatusTeapot, resp1.StatusCode)

	resp2, _ := http.Get(srv.URL + "/std")
	assert.Equal(t, http.StatusInternalServerError, resp2.StatusCode)
}

func TestRouter_Mount(t *testing.T) {
	r := router.New()

	subMux := http.NewServeMux()
	// Router.Mount does not strip prefixes. The sub-mux sees the full path.
	subMux.HandleFunc("/mnt/check", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	r.Mount("/mnt/", subMux)

	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/mnt/check")
	require.NoError(t, err)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

func TestRouter_Middleware(t *testing.T) {
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

	resp, _ := http.Get(srv.URL + "/")
	assert.Equal(t, "true", resp.Header.Get("X-Global"))
}
