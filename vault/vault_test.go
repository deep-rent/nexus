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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/router"
	"github.com/deep-rent/nexus/vault"
	"github.com/deep-rent/nexus/vault/store/mock"
)

// mockHint implements jwk.Hint for testing.
type mockHint struct {
	alg string
	kid string
}

func (h mockHint) Algorithm() string { return h.alg }
func (h mockHint) KeyID() string     { return h.kid }

func generateTestKeyPair(t *testing.T, kid string) jwk.KeyPair {
	t.Helper()
	prv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	return jwk.NewKeyBuilder(jwa.RS256).WithKeyID(kid).BuildPair(prv)
}

func TestVault_Active(t *testing.T) {
	ctx := context.Background()
	kek := []byte("01234567890123456789012345678901") // 32 bytes
	
	key1 := generateTestKeyPair(t, "key-1") // older
	key2 := generateTestKeyPair(t, "key-2") // newer (active)

	t.Run("success", func(t *testing.T) {
		src := mock.New(kek)
		// Because mock Load returns in reverse chronological order, 
		// the last prepopulated key is returned first (active).
		src.Prepopulate(key1, key2)
		v := vault.New(src, kek)

		active, err := v.Next(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if active.KeyID() != "key-2" {
			t.Errorf("expected active kid %q, got %q", "key-2", active.KeyID())
		}
	})

	t.Run("empty vault", func(t *testing.T) {
		src := mock.New(kek)
		v := vault.New(src, kek)

		_, err := v.Next(ctx)
		if !errors.Is(err, vault.ErrKeyNotFound) {
			t.Errorf("expected ErrKeyNotFound, got %v", err)
		}
	})

	t.Run("source error", func(t *testing.T) {
		src := mock.New(kek)
		src.Prepopulate(key1)
		v := vault.New(src, []byte("wrong-kek-will-cause-error"))

		_, err := v.Next(ctx)
		if err == nil {
			t.Errorf("expected error due to invalid KEK, got nil")
		}
	})
}

func TestVault_Find(t *testing.T) {
	ctx := context.Background()
	kek := []byte("01234567890123456789012345678901")
	key1 := generateTestKeyPair(t, "key-1")
	key2 := generateTestKeyPair(t, "key-2")
	
	src := mock.New(kek)
	src.Prepopulate(key1, key2)
	v := vault.New(src, kek)

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
	kek := []byte("01234567890123456789012345678901")
	key1 := generateTestKeyPair(t, "key-1")
	key2 := generateTestKeyPair(t, "key-2")
	
	src := mock.New(kek)
	src.Prepopulate(key1, key2)
	v := vault.New(src, kek)

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

func TestProvider_ServeHTTP(t *testing.T) {
	kek := []byte("01234567890123456789012345678901")
	key1 := generateTestKeyPair(t, "key-A")
	key2 := generateTestKeyPair(t, "key-B")

	src := mock.New(kek)
	src.Prepopulate(key1, key2)
	v := vault.New(src, kek)
	p := vault.NewProvider(v)

	r := router.New()
	r.Handle("GET /jwks", p)

	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", res.StatusCode)
	}

	if res.Header.Get("Content-Type") != "application/jwk-set+json" {
		t.Errorf("unexpected content type: %s", res.Header.Get("Content-Type"))
	}

	etag := res.Header.Get("ETag")
	if etag == "" {
		t.Errorf("expected ETag header")
	}

	lastMod := res.Header.Get("Last-Modified")
	if lastMod == "" {
		t.Errorf("expected Last-Modified header")
	}

	// Test If-None-Match
	req2 := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	req2.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()

	r.ServeHTTP(rec2, req2)
	if rec2.Result().StatusCode != http.StatusNotModified {
		t.Errorf("expected status 304, got %d", rec2.Result().StatusCode)
	}

	// Test If-Modified-Since
	req3 := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	// Add 1 second to last mod to simulate future request
	parsedLastMod, _ := time.Parse(http.TimeFormat, lastMod)
	req3.Header.Set("If-Modified-Since", parsedLastMod.Add(time.Second).Format(http.TimeFormat))
	rec3 := httptest.NewRecorder()

	r.ServeHTTP(rec3, req3)
	if rec3.Result().StatusCode != http.StatusNotModified {
		t.Errorf("expected status 304, got %d", rec3.Result().StatusCode)
	}
}
