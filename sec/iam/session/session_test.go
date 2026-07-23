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

package session_test

import (
	"errors"
	"testing"
	"time"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/iam/artifact"
	"github.com/deep-rent/nexus/sec/iam/session"
	"github.com/deep-rent/nexus/std/clock"
)

// env bundles a manager with its store and a controllable clock.
type env struct {
	store   *artifact.Map[string, session.Record]
	manager *session.Manager
	now     time.Time
}

func newEnv(t *testing.T, opts ...session.Option) *env {
	t.Helper()
	e := &env{
		store: artifact.NewMap(
			func(r session.Record) string { return r.ID },
		),
		now: time.Unix(1_752_000_000, 0),
	}
	e.manager = session.New(
		e.store,
		append([]session.Option{
			session.WithClock(clock.Clock(func() time.Time { return e.now })),
		}, opts...)...,
	)
	return e
}

func TestManager_EstablishAndResolve(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	key, err := e.manager.Establish(t.Context(), "alice", time.Hour)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	if key == "" {
		t.Fatal("Establish returned an empty key")
	}

	// The store must never see the plaintext key.
	if _, found, _ := e.store.Get(t.Context(), key); found {
		t.Error("plaintext key used as storage key")
	}
	r, found, _ := e.store.Get(
		t.Context(),
		digest.DefaultHasher.String(key),
	)
	if !found {
		t.Fatal("record not stored under the key digest")
	}
	if r.Owner != "alice" {
		t.Errorf("stored owner = %q; want alice", r.Owner)
	}
	if want := e.now.Add(time.Hour).Unix(); r.ExpiresAt != want {
		t.Errorf("got expiry %d; want %d", r.ExpiresAt, want)
	}

	owner, ok, err := e.manager.Resolve(t.Context(), key)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !ok || owner != "alice" {
		t.Errorf("got (%q, %t); want (alice, true)", owner, ok)
	}
}

func TestManager_ResolveRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(e *env) (key string)
	}{
		{
			name:  "empty key",
			setup: func(e *env) string { return "" },
		},
		{
			name:  "unknown key",
			setup: func(e *env) string { return "no-such-key" },
		},
		{
			name: "expired",
			setup: func(e *env) string {
				key, err := e.manager.Establish(
					t.Context(), "alice", time.Hour,
				)
				if err != nil {
					t.Fatalf("Establish: %v", err)
				}
				e.now = e.now.Add(time.Hour + time.Second)
				return key
			},
		},
		{
			name: "destroyed",
			setup: func(e *env) string {
				key, err := e.manager.Establish(
					t.Context(), "alice", time.Hour,
				)
				if err != nil {
					t.Fatalf("Establish: %v", err)
				}
				if _, err := e.manager.Destroy(t.Context(), key); err != nil {
					t.Fatalf("Destroy: %v", err)
				}
				return key
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			key := tt.setup(e)

			if _, ok, err := e.manager.Resolve(t.Context(), key); err != nil {
				t.Fatalf("Resolve: %v", err)
			} else if ok {
				t.Error("session should not resolve")
			}
		})
	}
}

func TestManager_NonExpiring(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	key, err := e.manager.Establish(t.Context(), "alice", 0)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}

	// A nonpositive lifetime stores a session without server-side expiry.
	e.now = e.now.Add(1000 * time.Hour)
	if _, ok, _ := e.manager.Resolve(t.Context(), key); !ok {
		t.Error("non-expiring session should still resolve")
	}
}

func TestManager_Destroy(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	key, err := e.manager.Establish(t.Context(), "alice", time.Hour)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}

	if deleted, err := e.manager.Destroy(
		t.Context(),
		key,
	); err != nil ||
		!deleted {
		t.Fatalf("Destroy: got (%t, %v); want (true, nil)", deleted, err)
	}
	if deleted, _ := e.manager.Destroy(t.Context(), key); deleted {
		t.Error("second Destroy should report nothing removed")
	}
	if deleted, err := e.manager.Destroy(
		t.Context(),
		"",
	); deleted ||
		err != nil {
		t.Error("Destroy of an empty key should be a no-op")
	}
}

func TestManager_StorageErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	boom := errors.New("store down")

	key, err := e.manager.Establish(t.Context(), "alice", time.Hour)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}

	e.store.Err = boom

	if _, err := e.manager.Establish(
		t.Context(), "alice", time.Hour,
	); !errors.Is(err, boom) {
		t.Errorf("Establish: got %v; want the storage error", err)
	}
	if _, _, err := e.manager.Resolve(t.Context(), key); !errors.Is(err, boom) {
		t.Errorf("Resolve: got %v; want the storage error", err)
	}
	if _, err := e.manager.Destroy(t.Context(), key); !errors.Is(err, boom) {
		t.Errorf("Destroy: got %v; want the storage error", err)
	}
}

func TestManager_CustomHasher(t *testing.T) {
	t.Parallel()

	hasher := digest.New(nil) // fresh hasher instance, default algorithm
	e := newEnv(t, session.WithHasher(hasher))

	key, err := e.manager.Establish(t.Context(), "alice", time.Hour)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	if _, found, _ := e.store.Get(t.Context(), hasher.String(key)); !found {
		t.Error("record not keyed by the injected hasher's digest")
	}
}

func TestNew_PanicsWithoutStore(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("New(nil) did not panic")
		}
	}()
	session.New(nil)
}
