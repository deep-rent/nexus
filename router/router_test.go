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

// mockHandler allows us to test Handler interface compliance.
type mockHandler struct{}

func (m *mockHandler) ServeHTTP(e *router.Exchange) error {
	return e.Status(http.StatusOK)
}

func TestExchange_BindJSON(t *testing.T) {
	type args struct {
		contentType string
		body        *strings.Reader
		isNilBody   bool // Force nil body for httptest
	}
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		wantReason string
		wantStatus int
	}{
		{
			name: "success",
			args: args{
				contentType: "application/json",
				body:        strings.NewReader(`{"name":"test"}`),
			},
			wantErr: false,
		},
		{
			name: "failure_wrong_content_type",
			args: args{
				contentType: "text/plain",
				body:        strings.NewReader(`{}`),
			},
			wantErr:    true,
			wantReason: router.ReasonWrongType,
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name: "failure_empty_body_nil",
			args: args{
				contentType: "application/json",
				isNilBody:   true,
			},
			wantErr:    true,
			wantReason: router.ReasonEmptyBody,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "failure_malformed_json",
			args: args{
				contentType: "application/json",
				body:        strings.NewReader(`{"name":`),
			},
			wantErr:    true,
			wantReason: router.ReasonParseJSON,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r *http.Request
			if tt.args.isNilBody {
				r = httptest.NewRequest(http.MethodPost, "/", nil)
			} else {
				r = httptest.NewRequest(http.MethodPost, "/", tt.args.body)
			}

			// We must set the header manually as httptest doesn't infer it
			if tt.args.contentType != "" {
				r.Header.Set("Content-Type", tt.args.contentType)
			}

			e := &router.Exchange{R: r}
			var v map[string]string

			err := e.BindJSON(&v)

			if tt.wantErr {
				require.Error(t, err)
				var ae *router.Error
				require.True(t, errors.As(err, &ae))
				assert.Equal(t, tt.wantReason, ae.Reason)
				assert.Equal(t, tt.wantStatus, ae.Status)
			} else {
				assert.NoError(t, err)
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

	err := e.Status(http.StatusNoContent)

	require.NoError(t, err)
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
	req.SetPathValue("id", "123") // Simulate Go 1.22 path matching
	rec := httptest.NewRecorder()
	e := &router.Exchange{R: req, W: rec}

	assert.Equal(t, http.MethodGet, e.Method())
	assert.Equal(t, "/users/123", e.Path())
	assert.NotNil(t, e.URL())
	assert.NotNil(t, e.Context())
	assert.Equal(t, "123", e.Param("id"))
	assert.Equal(t, "search", e.Query().Get("q"))

	// Header helpers
	req.Header.Set("X-In", "foo")
	assert.Equal(t, "foo", e.GetHeader("X-In"))

	e.SetHeader("X-Out", "bar")
	assert.Equal(t, "bar", rec.Header().Get("X-Out"))
}

func TestRouter_Handle_Integration(t *testing.T) {
	r := router.New()

	// Test HandleFunc
	r.HandleFunc("GET /func", func(e *router.Exchange) error {
		return e.JSON(http.StatusOK, map[string]string{"type": "func"})
	})

	// Test Handle with Interface
	r.Handle("GET /struct", &mockHandler{})

	srv := httptest.NewServer(r)
	defer srv.Close()

	// 1. Assert Func
	resp, err := http.Get(srv.URL + "/func")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 2. Assert Struct
	resp2, err := http.Get(srv.URL + "/struct")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

func TestRouter_ErrorHandling(t *testing.T) {
	r := router.New()

	// 1. Typed API Error
	r.HandleFunc("GET /typed", func(e *router.Exchange) error {
		return &router.Error{
			Status: http.StatusTeapot,
			Reason: "tea_time",
		}
	})

	// 2. Standard Go Error (should become 500)
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
	// Note: http.ServeMux does not strip prefixes by default.
	// The sub-mux sees the full path "/mnt/check".
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
	// Simple middleware that sets a header
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Global", "true")
			next.ServeHTTP(w, r)
		})
	}

	r := router.New(router.WithMiddleware(mw))
	r.HandleFunc("GET /", func(e *router.Exchange) error {
		return e.Status(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/")
	assert.Equal(t, "true", resp.Header.Get("X-Global"))
}
