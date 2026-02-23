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

package updater_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/deep-rent/nexus/updater"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("panics", func(t *testing.T) {
		assert.PanicsWithValue(t, "updater: owner is required", func() {
			updater.New(&updater.Config{Repository: "r", Current: "v1.0.0"})
		})
		assert.PanicsWithValue(t, "updater: repository is required", func() {
			updater.New(&updater.Config{Owner: "o", Current: "v1.0.0"})
		})
		assert.PanicsWithValue(t, "updater: current version is required", func() {
			updater.New(&updater.Config{Owner: "o", Repository: "r"})
		})
		assert.Panics(t, func() {
			updater.New(&updater.Config{
				Owner:      "o",
				Repository: "r",
				Current:    "invalid",
			})
		})
	})

	t.Run("success", func(t *testing.T) {
		u := updater.New(&updater.Config{
			Owner:      "o",
			Repository: "r",
			Current:    "1.0.0", // Should be normalized.
		})
		assert.NotNil(t, u)
	})
}

func TestCheck(t *testing.T) {
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
			name:    "update available (no v prefix)",
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := r.URL.Path
				assert.Equal(t, "/repos/owner/repo/releases/latest", path)
				accept := r.Header.Get("Accept")
				assert.Equal(t, "application/vnd.github.v3+json", accept)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			s := httptest.NewServer(h)
			defer s.Close()

			cfg := &updater.Config{
				BaseURL:    s.URL,
				Owner:      "owner",
				Repository: "repo",
				Current:    tc.current,
			}

			got, err := updater.Check(context.Background(), cfg)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			if tc.want == "" {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tc.want, got.Version)
			}
		})
	}
}

func TestCheck_NetworkError(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	s.Close() // Force a connection error.

	cfg := &updater.Config{
		BaseURL:    s.URL,
		Owner:      "o",
		Repository: "r",
		Current:    "v1.0.0",
		Timeout:    100 * time.Millisecond,
	}
	_, err := updater.Check(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch")
}

func TestCheck_UserAgent(t *testing.T) {
	ua := "TestAgent/1.0"

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, ua, r.Header.Get("User-Agent"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tag_name": "v1.0.0"}`))
	})
	s := httptest.NewServer(h)
	defer s.Close()

	cfg := &updater.Config{
		BaseURL:    s.URL,
		Owner:      "o",
		Repository: "r",
		Current:    "v1.0.0",
		UserAgent:  ua,
	}
	_, err := updater.Check(context.Background(), cfg)
	require.NoError(t, err)
}
