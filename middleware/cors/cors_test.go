package cors_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deep-rent/nexus/middleware/cors"
)

func TestCorsMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		opts           []cors.Option
		reqMethod      string
		reqHeaders     map[string]string
		wantStatusCode int
		wantResHeaders map[string]string
		wantNextCalled bool
	}{
		{
			name:           "Non-CORS request without Origin header",
			opts:           []cors.Option{cors.WithAllowedOrigins("http://a.com")},
			reqMethod:      http.MethodGet,
			reqHeaders:     nil,
			wantStatusCode: http.StatusOK,
			wantResHeaders: nil,
			wantNextCalled: true,
		},
		{
			name:           "Actual request with default settings (allow all)",
			opts:           nil,
			reqMethod:      http.MethodGet,
			reqHeaders:     map[string]string{"Origin": "http://a.com"},
			wantStatusCode: http.StatusOK,
			wantResHeaders: map[string]string{
				"Access-Control-Allow-Origin": "*",
				"Vary":                        "Origin",
			},
			wantNextCalled: true,
		},
		{
			name:      "Preflight request with default settings",
			opts:      nil,
			reqMethod: http.MethodOptions,
			reqHeaders: map[string]string{
				"Origin":                        "http://a.com",
				"Access-Control-Request-Method": "GET",
			},
			wantStatusCode: http.StatusNoContent,
			wantResHeaders: map[string]string{
				"Access-Control-Allow-Origin": "*",
				"Vary":                        "Origin",
			},
			wantNextCalled: false,
		},
		{
			name:           "Invalid preflight request without request method passes through",
			opts:           []cors.Option{cors.WithAllowedMethods(http.MethodPut)},
			reqMethod:      http.MethodOptions,
			reqHeaders:     map[string]string{"Origin": "http://a.com"},
			wantStatusCode: http.StatusOK,
			wantResHeaders: nil,
			wantNextCalled: true,
		},
		{
			name:           "Request with disallowed origin passes through",
			opts:           []cors.Option{cors.WithAllowedOrigins("http://a.com")},
			reqMethod:      http.MethodGet,
			reqHeaders:     map[string]string{"Origin": "http://b.com"},
			wantStatusCode: http.StatusOK,
			wantResHeaders: nil,
			wantNextCalled: true,
		},
		{
			name: "Preflight request with full configuration",
			opts: []cors.Option{
				cors.WithAllowedOrigins("http://a.com"),
				cors.WithAllowedMethods(http.MethodPut, http.MethodPatch),
				cors.WithAllowedHeaders("X-Custom-Header"),
				cors.WithMaxAge(12 * time.Hour),
			},
			reqMethod: http.MethodOptions,
			reqHeaders: map[string]string{
				"Origin":                         "http://a.com",
				"Access-Control-Request-Method":  "PUT",
				"Access-Control-Request-Headers": "X-Custom-Header",
			},
			wantStatusCode: http.StatusNoContent,
			wantResHeaders: map[string]string{
				"Access-Control-Allow-Origin":  "http://a.com",
				"Access-Control-Allow-Methods": "PUT, PATCH",
				"Access-Control-Allow-Headers": "X-Custom-Header",
				"Access-Control-Max-Age":       "43200",
				"Vary":                         "Origin",
			},
			wantNextCalled: false,
		},
		{
			name: "Actual request with exposed headers",
			opts: []cors.Option{
				cors.WithAllowedOrigins("http://a.com"),
				cors.WithExposedHeaders("X-Pagination-Total"),
			},
			reqMethod:      http.MethodGet,
			reqHeaders:     map[string]string{"Origin": "http://a.com"},
			wantStatusCode: http.StatusOK,
			wantResHeaders: map[string]string{
				"Access-Control-Allow-Origin":   "http://a.com",
				"Access-Control-Expose-Headers": "X-Pagination-Total",
				"Vary":                          "Origin",
			},
			wantNextCalled: true,
		},
		{
			name: "Actual request with credentials + allowed origin reflects origin",
			opts: []cors.Option{
				cors.WithAllowCredentials(true),
				cors.WithAllowedOrigins("http://a.com", "http://b.com"),
			},
			reqMethod:      http.MethodGet,
			reqHeaders:     map[string]string{"Origin": "http://b.com"},
			wantStatusCode: http.StatusOK,
			wantResHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "http://b.com",
				"Access-Control-Allow-Credentials": "true",
				"Vary":                             "Origin",
			},
			wantNextCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			handler := cors.New(tt.opts...)(next)
			r := httptest.NewRequest(tt.reqMethod, "/", nil)
			for k, v := range tt.reqHeaders {
				r.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			require.Equal(t, tt.wantStatusCode, w.Code)
			assert.Equal(t, tt.wantNextCalled, nextCalled)

			if tt.wantResHeaders == nil {
				for h := range w.Header() {
					assert.NotContains(t, strings.ToLower(h), "access-control-")
				}
			} else {
				for k, v := range tt.wantResHeaders {
					assert.Equal(t, v, w.Header().Get(k))
				}
			}
		})
	}
}
