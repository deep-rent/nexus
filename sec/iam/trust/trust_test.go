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

package trust_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/iam/artifact"
	"github.com/deep-rent/nexus/sec/iam/trust"
)

// fakeStore is an in-memory [trust.Store]: an [artifact.Map] extended by the
// owner-scoped bulk deletion.
type fakeStore struct {
	*artifact.Map[string, trust.Record]
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		Map: artifact.NewMap(func(r trust.Record) string { return r.ID }),
	}
}

func (s *fakeStore) DeleteForOwner(ctx context.Context, owner string) error {
	if s.Err != nil {
		return s.Err
	}
	s.Range(func(id string, r trust.Record) bool {
		if r.Owner == owner {
			_, _ = s.Delete(ctx, id)
		}
		return true
	})
	return nil
}

var _ trust.Store = (*fakeStore)(nil)

// env bundles a manager with its store and a controllable clock.
type env struct {
	store   *fakeStore
	manager *trust.Manager
	now     time.Time
}

func newEnv(t *testing.T, opts ...trust.Option) *env {
	t.Helper()
	e := &env{
		store: newFakeStore(),
		now:   time.Unix(1_752_000_000, 0),
	}
	e.manager = trust.New(
		e.store,
		append([]trust.Option{
			trust.WithClock(func() time.Time { return e.now }),
		}, opts...)...,
	)
	return e
}

func TestManager_IssueAndCheck(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	token, err := e.manager.Issue(t.Context(), "alice", "iPhone")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if token == "" {
		t.Fatal("Issue returned an empty token")
	}

	// The store must never see the plaintext token.
	if _, found, _ := e.store.Get(t.Context(), token); found {
		t.Error("plaintext token used as storage key")
	}
	r, found, _ := e.store.Get(
		t.Context(),
		digest.DefaultHasher.String(token),
	)
	if !found {
		t.Fatal("record not stored under the token digest")
	}
	if r.Owner != "alice" || r.Label != "iPhone" {
		t.Errorf("stored record = %+v; want owner alice, label iPhone", r)
	}
	if want := e.now.Add(trust.DefaultLifetime).Unix(); r.ExpiresAt != want {
		t.Errorf("got expiry %d; want %d", r.ExpiresAt, want)
	}

	dev, err := e.manager.Check(t.Context(), token, "alice")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !dev.Trusted {
		t.Error("device should be trusted for the enrolling owner")
	}
	if dev.ID != r.ID {
		t.Errorf("got device ID %q; want record ID %q", dev.ID, r.ID)
	}
}

func TestManager_CheckRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(e *env) (token, owner string)
	}{
		{
			name: "empty token",
			setup: func(e *env) (string, string) {
				return "", "alice"
			},
		},
		{
			name: "unknown token",
			setup: func(e *env) (string, string) {
				return "no-such-token", "alice"
			},
		},
		{
			name: "wrong owner",
			setup: func(e *env) (string, string) {
				token, err := e.manager.Issue(t.Context(), "alice", "")
				if err != nil {
					t.Fatalf("Issue: %v", err)
				}
				return token, "mallory"
			},
		},
		{
			name: "expired",
			setup: func(e *env) (string, string) {
				token, err := e.manager.Issue(t.Context(), "alice", "")
				if err != nil {
					t.Fatalf("Issue: %v", err)
				}
				e.now = e.now.Add(trust.DefaultLifetime + time.Second)
				return token, "alice"
			},
		},
		{
			name: "revoked",
			setup: func(e *env) (string, string) {
				token, err := e.manager.Issue(t.Context(), "alice", "")
				if err != nil {
					t.Fatalf("Issue: %v", err)
				}
				if err := e.manager.Revoke(t.Context(), token); err != nil {
					t.Fatalf("Revoke: %v", err)
				}
				return token, "alice"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			token, owner := tt.setup(e)

			dev, err := e.manager.Check(t.Context(), token, owner)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if dev.Trusted {
				t.Error("device should not be trusted")
			}
		})
	}
}

func TestManager_Lifetime(t *testing.T) {
	t.Parallel()
	e := newEnv(t, trust.WithLifetime(time.Hour))

	token, err := e.manager.Issue(t.Context(), "alice", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Still trusted just before the window closes.
	e.now = e.now.Add(time.Hour - time.Second)
	if dev, _ := e.manager.Check(t.Context(), token, "alice"); !dev.Trusted {
		t.Error("device should still be trusted within the window")
	}

	// No longer trusted once it lapses.
	e.now = e.now.Add(2 * time.Second)
	if dev, _ := e.manager.Check(t.Context(), token, "alice"); dev.Trusted {
		t.Error("device should not be trusted past the window")
	}
}

func TestManager_RevokeAll(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	t1, _ := e.manager.Issue(t.Context(), "alice", "phone")
	t2, _ := e.manager.Issue(t.Context(), "alice", "laptop")
	t3, _ := e.manager.Issue(t.Context(), "bob", "tablet")

	if err := e.manager.RevokeAll(t.Context(), "alice"); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	for _, token := range []string{t1, t2} {
		if dev, _ := e.manager.Check(t.Context(), token, "alice"); dev.Trusted {
			t.Error("alice's devices should have been revoked")
		}
	}
	if dev, _ := e.manager.Check(t.Context(), t3, "bob"); !dev.Trusted {
		t.Error("bob's device should be unaffected")
	}
}

func TestManager_RevokeEmptyToken(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	if err := e.manager.Revoke(t.Context(), ""); err != nil {
		t.Fatalf("Revoke of an empty token should be a no-op: %v", err)
	}
}

func TestManager_StorageErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	boom := errors.New("store down")

	token, err := e.manager.Issue(t.Context(), "alice", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	e.store.Err = boom

	if _, err := e.manager.Issue(
		t.Context(),
		"alice",
		"",
	); !errors.Is(
		err,
		boom,
	) {
		t.Errorf("Issue: got %v; want the storage error", err)
	}
	if _, err := e.manager.Check(
		t.Context(),
		token,
		"alice",
	); !errors.Is(
		err,
		boom,
	) {
		t.Errorf("Check: got %v; want the storage error", err)
	}
	if err := e.manager.Revoke(t.Context(), token); !errors.Is(err, boom) {
		t.Errorf("Revoke: got %v; want the storage error", err)
	}
	if err := e.manager.RevokeAll(t.Context(), "alice"); !errors.Is(err, boom) {
		t.Errorf("RevokeAll: got %v; want the storage error", err)
	}
}

func TestManager_CustomHasher(t *testing.T) {
	t.Parallel()

	hasher := digest.New(nil) // fresh hasher instance, default algorithm
	e := newEnv(t, trust.WithHasher(hasher))

	token, err := e.manager.Issue(t.Context(), "alice", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, found, _ := e.store.Get(t.Context(), hasher.String(token)); !found {
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
	trust.New(nil)
}
