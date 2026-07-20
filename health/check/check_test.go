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

package check_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/health"
	"github.com/deep-rent/nexus/health/check"
)

func TestTCP(t *testing.T) {
	t.Parallel()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer func() {
		_ = l.Close()
	}()

	addr := l.Addr().String()
	free := "127.0.0.1:0"

	tests := []struct {
		name       string
		addr       string
		timeout    time.Duration
		wantStatus health.Status
		wantErr    bool
	}{
		{
			name:       "healthy connection",
			addr:       addr,
			timeout:    time.Second,
			wantStatus: health.StatusHealthy,
			wantErr:    false,
		},
		{
			name:       "connection refused",
			addr:       free,
			timeout:    10 * time.Millisecond,
			wantStatus: health.StatusSick,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// t.Parallel()

			chk := check.TCP(tt.addr, tt.timeout)
			status, err := chk(t.Context())

			if status != tt.wantStatus {
				t.Errorf("status: got %q; want %q", status, tt.wantStatus)
			}

			if (err != nil) != tt.wantErr {
				if tt.wantErr {
					t.Error("should have returned an error")
				} else {
					t.Errorf("should not have returned an error: %v", err)
				}
			}
		})
	}
}

func TestHTTP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		handler    http.HandlerFunc
		client     *http.Client
		wantStatus health.Status
		wantErr    bool
	}{
		{
			name: "200 ok",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			wantStatus: health.StatusHealthy,
			wantErr:    false,
		},
		{
			name: "204 no content",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
			wantStatus: health.StatusHealthy,
			wantErr:    false,
		},
		{
			name: "400 bad request",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			},
			wantStatus: health.StatusSick,
			wantErr:    true,
		},
		{
			name: "500 internal server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantStatus: health.StatusSick,
			wantErr:    true,
		},
		{
			name: "custom client healthy",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			client:     &http.Client{Timeout: 2 * time.Second},
			wantStatus: health.StatusHealthy,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := tt.client
			if client == nil {
				client = &http.Client{
					Timeout: 1 * time.Second,
				}
			}
			chk := check.HTTP(server.URL, check.WithClient(client))
			status, err := chk(t.Context())

			if status != tt.wantStatus {
				t.Errorf("status: got %q; want %q", status, tt.wantStatus)
			}

			if (err != nil) != tt.wantErr {
				if tt.wantErr {
					t.Error("should have returned an error")
				} else {
					t.Errorf("should not have returned an error: %v", err)
				}
			}
		})
	}
}

func TestHTTP_Unreachable(t *testing.T) {
	t.Parallel()

	const url = "http://127.0.0.1:0/invalid"
	chk := check.HTTP(url, check.WithClient(&http.Client{
		Timeout: 1 * time.Second,
	}))
	status, err := chk(t.Context())

	if got, want := status, health.StatusSick; got != want {
		t.Errorf("status: got %q; want %q", got, want)
	}

	if err == nil {
		t.Error("should have returned an error")
	}
}

func TestHTTP_Timeout(t *testing.T) {
	t.Parallel()

	h := func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}
	server := httptest.NewServer(http.HandlerFunc(h))
	defer server.Close()

	client := &http.Client{Timeout: 10 * time.Millisecond}
	chk := check.HTTP(server.URL, check.WithClient(client))

	status, err := chk(t.Context())

	if got, want := status, health.StatusSick; got != want {
		t.Errorf("status: got %q; want %q", got, want)
	}

	if err == nil {
		t.Fatal("should have returned an error")
	}

	if msg := err.Error(); !strings.Contains(msg, "Timeout") &&
		!strings.Contains(msg, "context deadline exceeded") {
		t.Errorf("error: want timeout info; got %q", msg)
	}
}

type mockPinger struct{ err error }

func (m *mockPinger) PingContext(ctx context.Context) error {
	return m.err
}

func TestPing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pinger     check.Pinger
		wantStatus health.Status
		wantErr    bool
	}{
		{
			name:       "healthy ping",
			pinger:     &mockPinger{err: nil},
			wantStatus: health.StatusHealthy,
			wantErr:    false,
		},
		{
			name:       "sick ping",
			pinger:     &mockPinger{err: errors.New("db disconnected")},
			wantStatus: health.StatusSick,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			chk := check.Ping(tt.pinger)
			status, err := chk(t.Context())

			if status != tt.wantStatus {
				t.Errorf("status: got %q; want %q", status, tt.wantStatus)
			}

			if (err != nil) != tt.wantErr {
				if tt.wantErr {
					t.Error("should have returned an error")
				} else {
					t.Errorf("should not have returned an error: %v", err)
				}
			}
		})
	}
}

func TestDNS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		host       string
		wantStatus health.Status
		wantErr    bool
	}{
		{
			name:       "resolvable host",
			host:       "localhost",
			wantStatus: health.StatusHealthy,
			wantErr:    false,
		},
		{
			name:       "unresolvable host",
			host:       "this.is.an.invalid.domain.test.",
			wantStatus: health.StatusSick,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			chk := check.DNS(tt.host)
			status, err := chk(t.Context())

			if status != tt.wantStatus {
				t.Errorf("status: got %q; want %q", status, tt.wantStatus)
			}

			if (err != nil) != tt.wantErr {
				if tt.wantErr {
					t.Error("should have returned an error")
				} else {
					t.Errorf("should not have returned an error: %v", err)
				}
			}
		})
	}
}

func TestWrappers(t *testing.T) {
	t.Parallel()

	errFail := errors.New("fail")

	tests := []struct {
		name       string
		chk        health.CheckFunc
		wantStatus health.Status
		wantErr    error
	}{
		{
			name: "wrap success",
			chk: check.Wrap(func() error {
				return nil
			}),
			wantStatus: health.StatusHealthy,
			wantErr:    nil,
		},
		{
			name: "wrap failure",
			chk: check.Wrap(func() error {
				return errFail
			}),
			wantStatus: health.StatusSick,
			wantErr:    errFail,
		},
		{
			name: "wrap context success",
			chk: check.WrapContext(func(ctx context.Context) error {
				return nil
			}),
			wantStatus: health.StatusHealthy,
			wantErr:    nil,
		},
		{
			name: "wrap context failure",
			chk: check.WrapContext(func(ctx context.Context) error {
				return errFail
			}),
			wantStatus: health.StatusSick,
			wantErr:    errFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			status, err := tt.chk(t.Context())
			if status != tt.wantStatus {
				t.Errorf("status: got %q; want %q", status, tt.wantStatus)
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error: got %v; want %v", err, tt.wantErr)
			}
		})
	}
}

func TestWrapContext_PassesContext(t *testing.T) {
	t.Parallel()

	type contextKey struct{}
	const val = "nexus"

	ctx := context.WithValue(t.Context(), contextKey{}, val)

	chk := check.WrapContext(func(c context.Context) error {
		t.Helper()
		if got := c.Value(contextKey{}); got != val {
			t.Errorf("context value: got %v; want %v", got, val)
		}
		return nil
	})

	status, err := chk(ctx)
	if got, want := status, health.StatusHealthy; got != want {
		t.Errorf("status: got %q; want %q", got, want)
	}

	if err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}
}
