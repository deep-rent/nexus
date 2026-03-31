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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deep-rent/nexus/health"
	"github.com/deep-rent/nexus/health/check"
)

func TestTCP(t *testing.T) {
	// Start a dummy TCP server for the success case:
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	addr := l.Addr().String()
	free := "127.0.0.1:0" // A port that won't accept connections.

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
			addr:       free, // Connection will fail instantly or timeout.
			timeout:    10 * time.Millisecond,
			wantStatus: health.StatusSick,
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chk := check.TCP(tc.addr, tc.timeout)
			status, err := chk(context.Background())

			assert.Equal(t, tc.wantStatus, status)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHTTP(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		client     *http.Client
		wantStatus health.Status
		wantErr    bool
	}{
		{
			name: "200 OK",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			wantStatus: health.StatusHealthy,
			wantErr:    false,
		},
		{
			name: "204 No Content",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
			wantStatus: health.StatusHealthy,
			wantErr:    false,
		},
		{
			name: "400 Bad Request",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			},
			wantStatus: health.StatusSick,
			wantErr:    true,
		},
		{
			name: "500 Internal Server Error",
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(tc.handler)
			defer ts.Close()

			chk := check.HTTP(tc.client, ts.URL)
			status, err := chk(context.Background())

			assert.Equal(t, tc.wantStatus, status)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHTTP_Unreachable(t *testing.T) {
	// Tests the HTTP check against an invalid or unreachable URL:
	chk := check.HTTP(nil, "http://127.0.0.1:0/invalid")
	status, err := chk(context.Background())

	assert.Equal(t, health.StatusSick, status)
	assert.Error(t, err)
}

type mockPinger struct{ err error }

func (m *mockPinger) PingContext(ctx context.Context) error {
	return m.err
}

var _ check.Pinger = (*mockPinger)(nil)

func TestPing(t *testing.T) {
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chk := check.Ping(tc.pinger)
			status, err := chk(context.Background())

			assert.Equal(t, tc.wantStatus, status)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDNS(t *testing.T) {
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chk := check.DNS(tc.host)
			status, err := chk(context.Background())

			assert.Equal(t, tc.wantStatus, status)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWrappers(t *testing.T) {
	errFail := errors.New("fail")

	tests := []struct {
		name       string
		chk        health.CheckFunc
		wantStatus health.Status
		wantErr    error
	}{
		{
			name: "Wrap success",
			chk: check.Wrap(func() error {
				return nil
			}),
			wantStatus: health.StatusHealthy,
			wantErr:    nil,
		},
		{
			name: "Wrap failure",
			chk: check.Wrap(func() error {
				return errFail
			}),
			wantStatus: health.StatusSick,
			wantErr:    errFail,
		},
		{
			name: "WrapContext success",
			chk: check.WrapContext(func(ctx context.Context) error {
				return nil
			}),
			wantStatus: health.StatusHealthy,
			wantErr:    nil,
		},
		{
			name: "WrapContext failure",
			chk: check.WrapContext(func(ctx context.Context) error {
				return errFail
			}),
			wantStatus: health.StatusSick,
			wantErr:    errFail,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, err := tc.chk(context.Background())
			assert.Equal(t, tc.wantStatus, status)
			assert.Equal(t, tc.wantErr, err)
		})
	}
}
