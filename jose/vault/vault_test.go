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

package vault_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/vault"
)

// mockSource is a simple in-memory implementation of vault.Source for testing.
type mockSource struct {
	keys []jwk.KeyPair
	err  error
}

func (m *mockSource) Load(ctx context.Context) ([]jwk.KeyPair, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.keys, nil
}

// mockHint implements jwk.Hint for testing.
type mockHint struct {
	alg string
	kid string
	x5t string
}

func (h mockHint) Algorithm() string  { return h.alg }
func (h mockHint) KeyID() string      { return h.kid }
func (h mockHint) Thumbprint() string { return h.x5t }

func generateTestKeyPair(t *testing.T, kid string) jwk.KeyPair {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	builder := jwk.NewKeyBuilder(jwa.RS256).WithKeyID(kid)
	return builder.BuildPair(privateKey)
}

func TestVault_Active(t *testing.T) {
	ctx := context.Background()
	key1 := generateTestKeyPair(t, "key-1")
	key2 := generateTestKeyPair(t, "key-2")

	t.Run("success", func(t *testing.T) {
		src := &mockSource{keys: []jwk.KeyPair{key1, key2}}
		v := vault.New(src)

		active, err := v.Active(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if active.KeyID() != "key-1" {
			t.Errorf("expected active kid %q, got %q", "key-1", active.KeyID())
		}
	})

	t.Run("empty vault", func(t *testing.T) {
		src := &mockSource{keys: []jwk.KeyPair{}}
		v := vault.New(src)

		_, err := v.Active(ctx)
		if !errors.Is(err, vault.ErrKeyNotFound) {
			t.Errorf("expected ErrKeyNotFound, got %v", err)
		}
	})

	t.Run("source error", func(t *testing.T) {
		srcErr := errors.New("source error")
		src := &mockSource{err: srcErr}
		v := vault.New(src)

		_, err := v.Active(ctx)
		if !errors.Is(err, srcErr) {
			t.Errorf("expected %v, got %v", srcErr, err)
		}
	})
}

func TestVault_Find(t *testing.T) {
	ctx := context.Background()
	key1 := generateTestKeyPair(t, "key-1")
	key2 := generateTestKeyPair(t, "key-2")
	src := &mockSource{keys: []jwk.KeyPair{key1, key2}}
	v := vault.New(src)

	t.Run("found by kid", func(t *testing.T) {
		hint := mockHint{alg: jwa.RS256.String(), kid: "key-2"}
		k, err := v.Find(ctx, hint)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if k.KeyID() != "key-2" {
			t.Errorf("expected kid %q, got %q", "key-2", k.KeyID())
		}
	})

	t.Run("wrong algorithm", func(t *testing.T) {
		hint := mockHint{alg: "PS256", kid: "key-1"} // wrong alg
		_, err := v.Find(ctx, hint)
		if !errors.Is(err, vault.ErrKeyNotFound) {
			t.Errorf("expected ErrKeyNotFound, got %v", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		hint := mockHint{alg: jwa.RS256.String(), kid: "non-existent"}
		_, err := v.Find(ctx, hint)
		if !errors.Is(err, vault.ErrKeyNotFound) {
			t.Errorf("expected ErrKeyNotFound, got %v", err)
		}
	})

	t.Run("nil hint", func(t *testing.T) {
		_, err := v.Find(ctx, nil)
		if err == nil {
			t.Errorf("expected error for nil hint")
		}
	})
}

func TestVault_Keys(t *testing.T) {
	ctx := context.Background()
	key1 := generateTestKeyPair(t, "key-1")
	key2 := generateTestKeyPair(t, "key-2")
	src := &mockSource{keys: []jwk.KeyPair{key1, key2}}
	v := vault.New(src)

	keysIter, err := v.Keys(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int
	for range keysIter {
		count++
	}

	if count != 2 {
		t.Errorf("expected 2 keys, got %d", count)
	}
}
