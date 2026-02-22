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

package cors_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/deep-rent/nexus/middleware/cors"
)

func TestMiddleware(t *testing.T) {
	type test struct {
		name           string
		opts           []cors.Option
		reqMethod      string
		reqHeaders     map[string]string
		wantStatusCode int
		wantResHeaders map[string]string
		wantNextCalled bool
	}

	tests := []test{
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
			name:           "Invalid preflight request without method passes through",
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})

			handler := cors.New(tc.opts...)(next)
			r := httptest.NewRequest(tc.reqMethod, "/", nil)
			for k, v := range tc.reqHeaders {
				r.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			assert.Equal(t, tc.wantStatusCode, w.Code)
			assert.Equal(t, tc.wantNextCalled, called)

			if tc.wantResHeaders == nil {
				for h := range w.Header() {
					assert.NotContains(t, strings.ToLower(h), "access-control-")
				}
			} else {
				for k, v := range tc.wantResHeaders {
					assert.Equal(t, v, w.Header().Get(k))
				}
			}
		})
	}
}
