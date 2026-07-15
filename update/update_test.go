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

package update_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/update"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("panics", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name string
			give *update.Config
			want string
		}{
			{
				name: "owner is required",
				give: &update.Config{Repository: "r", Current: "v1.0.0"},
				want: "update: owner is required",
			},
			{
				name: "repository is required",
				give: &update.Config{Owner: "o", Current: "v1.0.0"},
				want: "update: repository is required",
			},
			{
				name: "current version is required",
				give: &update.Config{Owner: "o", Repository: "r"},
				want: "update: current version is required",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				defer func() {
					r := recover()
					if r == nil {
						t.Errorf("should have panicked with %q", tt.want)
					}
					if got, ok := r.(string); !ok || got != tt.want {
						t.Errorf("panic value: got %v; want %q", r, tt.want)
					}
				}()
				update.New(tt.give)
			})
		}

		t.Run("invalid semver", func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Error("should have panicked")
				}
			}()
			update.New(&update.Config{
				Owner:      "o",
				Repository: "r",
				Current:    "invalid",
			})
		})
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		u := update.New(&update.Config{
			Owner:      "o",
			Repository: "r",
			Current:    "1.0.0",
		})
		if u == nil {
			t.Fatal("updater should not be nil")
		}
	})
}

func TestCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		current string
		status  int
		body    string
		want    string
		wantErr string
	}{
		{
			name:    "update available",
			current: "v1.0.0",
			status:  http.StatusOK,
			body:    `{"tag_name": "v1.1.0", "html_url": "http://url"}`,
			want:    "v1.1.0",
		},
		{
			name:    "update available no v prefix",
			current: "1.0.0",
			status:  http.StatusOK,
			body:    `{"tag_name": "1.1.0", "html_url": "http://url"}`,
			want:    "1.1.0",
		},
		{
			name:    "no update",
			current: "v1.1.0",
			status:  http.StatusOK,
			body:    `{"tag_name": "v1.1.0"}`,
			want:    "",
		},
		{
			name:    "older version",
			current: "v1.2.0",
			status:  http.StatusOK,
			body:    `{"tag_name": "v1.1.0"}`,
			want:    "",
		},
		{
			name:    "invalid response json",
			current: "v1.0.0",
			status:  http.StatusOK,
			body:    `{invalid}`,
			wantErr: "failed to decode response body",
		},
		{
			name:    "api error",
			current: "v1.0.0",
			status:  http.StatusNotFound,
			body:    `{}`,
			wantErr: "unexpected status",
		},
		{
			name:    "invalid remote semver",
			current: "v1.0.0",
			status:  http.StatusOK,
			body:    `{"tag_name": "invalid"}`,
			wantErr: "not a valid semver",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					if got, want := r.URL.Path,
						"/repos/owner/repo/releases/latest"; got != want {
						t.Errorf("request path: got %q; want %q", got, want)
					}
					if got, want := r.Header.Get("Accept"),
						"application/vnd.github.v3+json"; got != want {
						t.Errorf("accept header: got %q; want %q", got, want)
					}
					w.WriteHeader(tt.status)
					_, _ = w.Write([]byte(tt.body))
				}))
			defer server.Close()

			cfg := &update.Config{
				BaseURL:    server.URL,
				Owner:      "owner",
				Repository: "repo",
				Current:    tt.current,
			}

			got, err := update.Check(t.Context(), cfg)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf(
						"should have returned an error matching %q", tt.wantErr,
					)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("want match for %q; got %q", tt.wantErr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}

			if tt.want == "" {
				if got != nil {
					t.Errorf("got %v; want nil", got)
				}
			} else {
				if got == nil {
					t.Fatal("release should not be nil")
				}
				if got.Version != tt.want {
					t.Errorf("version: got %q; want %q", got.Version, tt.want)
				}
			}
		})
	}
}

func TestCheck_NetworkError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()

	cfg := &update.Config{
		BaseURL:    server.URL,
		Owner:      "o",
		Repository: "r",
		Current:    "v1.0.0",
		Timeout:    100 * time.Millisecond,
	}

	_, err := update.Check(t.Context(), cfg)
	if err == nil {
		t.Fatal("should have returned a network error")
	}
	if got, want := err.Error(), "failed to fetch"; !strings.Contains(got, want) {
		t.Errorf("want match for %q; got %q", want, got)
	}
}

func TestCheck_UserAgent(t *testing.T) {
	t.Parallel()

	want := "TestAgent/1.0"
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("User-Agent"); got != want {
				t.Errorf("user agent: got %q; want %q", got, want)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"tag_name": "v1.0.0"}`))
		}))
	defer server.Close()

	cfg := &update.Config{
		BaseURL:    server.URL,
		Owner:      "o",
		Repository: "r",
		Current:    "v1.0.0",
		UserAgent:  want,
	}

	if _, err := update.Check(t.Context(), cfg); err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}
}

func TestCheck_Token(t *testing.T) {
	t.Parallel()

	want := "Bearer my-secret-token"
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != want {
				t.Errorf("authorization header: got %q; want %q", got, want)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"tag_name": "v1.0.0"}`))
		}))
	defer server.Close()

	cfg := &update.Config{
		BaseURL:    server.URL,
		Owner:      "o",
		Repository: "r",
		Current:    "v1.0.0",
		Token:      "my-secret-token",
	}

	if _, err := update.Check(t.Context(), cfg); err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}
}
