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

package jwk_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/sec/jose/jwa"
	"github.com/deep-rent/nexus/sec/jose/jwk"
	"github.com/deep-rent/nexus/net/router"
	"github.com/deep-rent/nexus/sec/sign"
)

type mockKey struct {
	kid string
	alg string
	mat any
}

func (k *mockKey) Algorithm() string       { return k.alg }
func (k *mockKey) KeyID() string           { return k.kid }
func (k *mockKey) Verify(_, _ []byte) bool { return true }
func (k *mockKey) Material() any           { return k.mat }

var _ jwk.Key = (*mockKey)(nil)

type mockHint struct {
	alg string
	kid string
}

func (h mockHint) Algorithm() string { return h.alg }
func (h mockHint) KeyID() string     { return h.kid }

var _ jwk.Hint = mockHint{}

func readTestFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec
	if err != nil {
		t.Fatalf(
			"test file %q: should not have returned an error: %v", name, err,
		)
	}
	return b
}

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		alg string
		kid string
		src string
	}{
		{
			"EdDSA",
			"P6rOVdsYhY_b0VzNdk568I9tYrAnBw-WGgsMZ2zMOvA",
			"Ed25519.json",
		},
		{
			"ES256",
			"chs_bZZOVng98tfs-pQRig3RTaXszdcZ0WsoyWORzDQ",
			"ES256.json",
		},
		{
			"ES384",
			"HCgaZlHgiGkHQ9f3Q2FWYs_NtZzQsLWaii8puMRbhhE",
			"ES384.json",
		},
		{
			"ES512",
			"3xQ6MwN6aFYouSGZyqv9DYvst-CV_12M58EvjJ6wHQs",
			"ES512.json",
		},
		{
			"PS256",
			"1iPDx07kLtDB6MeYwD451j-NUaZFv3QS4mFCCdIbaeQ",
			"PS256.json",
		},
		{
			"PS384",
			"5q0HzRnzOR2DivWMl4q2MpKXy8IdnfYMxc-c1s6Olhc",
			"PS384.json",
		},
		{
			"PS512",
			"6f-mwTH8QRxXXZHP7teEem1uqkGFYGPKSDxOqXc3xzQ",
			"PS512.json",
		},
		{
			"RS256",
			"KO4ZegrzU_W1RcC89v05Ev3C2JXHC2aQKNo08ZSbnC4",
			"RS256.json",
		},
		{
			"RS384",
			"g1jIq7AVMQRV3YHbLk3tJfHUJfwgVuzPzkMK3R1K_GU",
			"RS384.json",
		},
		{
			"RS512",
			"DYHSGgm9DBjiFYkciaL3lFjKDPJQc0BO6nS7IacanVU",
			"RS512.json",
		},
		{
			"ES256",
			"",
			"ecdsa_short_coordinate.json",
		},
		{
			"ML-DSA-44",
			"7tam8FslWbN0Rtzxb_gtJapvB-_lFrKfpC0b5GKBHkM",
			"ML-DSA-44.json",
		},
		{
			"ML-DSA-65",
			"VtgbFl3DTb_OEkrxX3OkMC0kGmhg9rv2b476rdUcp-c",
			"ML-DSA-65.json",
		},
		{
			"ML-DSA-87",
			"YQNE2_k-gXD8HxVvhhiiN2KZeLX8KX5OGjRLoDG00kA",
			"ML-DSA-87.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			t.Parallel()
			in := readTestFile(t, tt.src)

			key1, err := jwk.Parse(in)
			if err != nil {
				t.Fatalf(
					"parsing %q: should not have returned an error: %v",
					tt.src, err,
				)
			}
			if got, want := key1.Algorithm(), tt.alg; got != want {
				t.Errorf("key1 algorithm: got %q; want %q", got, want)
			}
			if got, want := key1.KeyID(), tt.kid; got != want {
				t.Errorf("key1 key id: got %q; want %q", got, want)
			}

			encoded, err := jwk.Write(key1)
			if err != nil {
				t.Fatalf("encoding: should not have returned an error: %v", err)
			}

			key2, err := jwk.Parse(encoded)
			if err != nil {
				t.Fatalf(
					"re-parsing: should not have returned an error: %v", err,
				)
			}
			if got, want := key2.Algorithm(), key1.Algorithm(); got != want {
				t.Errorf("key2 algorithm: got %q; want %q", got, want)
			}
			if got, want := key2.KeyID(), key1.KeyID(); got != want {
				t.Errorf("key2 key id: got %q; want %q", got, want)
			}
		})
	}
}

func TestParse_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		file string
	}{
		{"invalid key material", "invalid_key_material.json"},
		{"undefined key type", "undefined_key_type.json"},
		{"undefined algorithm", "undefined_algorithm.json"},
		{"unknown algorithm", "unknown_algorithm.json"},
		{"unsupported ECDSA curve", "unsupported_ecdsa_curve.json"},
		{"unsupported EdDSA curve", "unsupported_eddsa_curve.json"},
		{"ECDSA point not on curve", "ecdsa_not_on_curve.json"},
		{"ML-DSA wrong key size", "mldsa_wrong_key_size.json"},
		{"ML-DSA wrong key type", "mldsa_wrong_key_type.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := readTestFile(t, tt.file)
			if _, err := jwk.Parse(in); err == nil {
				t.Error("should have returned an error")
			}
		})
	}
}

func TestParseSet(t *testing.T) {
	t.Parallel()

	in := readTestFile(t, "set.json")

	set, err := jwk.ParseSet(in)
	if err != nil {
		t.Fatalf("parsing: should not have returned an error: %v", err)
	}
	if got, want := set.Len(), 10; got != want {
		t.Errorf("set size: got %d; want %d", got, want)
	}

	encoded, err := jwk.WriteSet(set)
	if err != nil {
		t.Fatalf("encoding: should not have returned an error: %v", err)
	}

	set2, err := jwk.ParseSet(encoded)
	if err != nil {
		t.Fatalf("re-parsing: should not have returned an error: %v", err)
	}
	if got, want := set2.Len(), set.Len(); got != want {
		t.Errorf("re-parsed set size: got %d; want %d", got, want)
	}

	for k := range set.Keys() {
		found := set2.Find(k)
		if found == nil {
			t.Errorf("key %q lost during round-trip", k.KeyID())
			continue
		}
		if got, want := found.KeyID(), k.KeyID(); got != want {
			t.Errorf("key id: got %q; want %q", got, want)
		}
	}
}

func TestParseSet_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		file string
	}{
		{"duplicate key id", "duplicate_key_id.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := readTestFile(t, tt.file)
			if _, err := jwk.ParseSet(in); err == nil {
				t.Error("should have returned an error")
			}
		})
	}
}

func TestParseSet_PartialSuccess(t *testing.T) {
	t.Parallel()

	set, err := jwk.ParseSet(readTestFile(t, "set_partial.json"))
	if err == nil {
		t.Error("should have returned an error")
	}
	if got, want := set.Len(), 2; got != want {
		t.Errorf("set size: got %d; want %d", got, want)
	}

	k1 := set.Find(&mockKey{alg: "ES256", kid: "valid-1"})
	if k1 == nil {
		t.Error("should have found valid-1")
	}
	k2 := set.Find(&mockKey{alg: "ES512", kid: "valid-2"})
	if k2 == nil {
		t.Error("should have found valid-2")
	}
}

func TestWrite_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     jwk.Key
		wantErr string
	}{
		{
			name: "unsupported algorithm",
			key: &mockKey{
				alg: "XY99",
				kid: "test",
			},
			wantErr: "unsupported algorithm",
		},
		{
			name: "mismatched RSA material",
			key: &mockKey{
				alg: jwa.RS256.String(),
				mat: &ecdsa.PublicKey{},
			},
			wantErr: "invalid key for algorithm \"RS256\"",
		},
		{
			name: "mismatched ECDSA material",
			key: &mockKey{
				alg: jwa.ES256.String(),
				mat: &rsa.PublicKey{},
			},
			wantErr: "invalid key for algorithm \"ES256\"",
		},
		{
			name: "mismatched EdDSA material",
			key: &mockKey{
				alg: jwa.EdDSA.String(),
				mat: &rsa.PublicKey{},
			},
			wantErr: "invalid key for algorithm \"EdDSA\"",
		},
		{
			name: "mismatched ML-DSA material",
			key: &mockKey{
				alg: jwa.MLDSA44.String(),
				mat: &rsa.PublicKey{},
			},
			wantErr: "invalid key for algorithm \"ML-DSA-44\"",
		},
		{
			name: "RSA zero exponent",
			key: &mockKey{
				alg: jwa.RS256.String(),
				mat: &rsa.PublicKey{N: big.NewInt(123), E: 0},
			},
			wantErr: "public exponent is zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := jwk.Write(tt.key)
			if err == nil {
				t.Fatal("should have returned an error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("got error %q; want it to contain %q",
					err, tt.wantErr)
			}
		})
	}
}

func TestWriteSet_Errors(t *testing.T) {
	t.Parallel()

	s := jwk.Singleton(&mockKey{alg: "XY99"})
	if _, err := jwk.WriteSet(s); err == nil {
		t.Error("should have returned an error")
	}
}

func TestSingleton(t *testing.T) {
	t.Parallel()

	key := &mockKey{
		kid: "kid",
		alg: "alg",
	}
	set := jwk.Singleton(key)
	if got, want := set.Len(), 1; got != want {
		t.Errorf("set size: got %d; want %d", got, want)
	}
	if got, want := set.Find(key), key; got != want {
		t.Errorf("found key: got %v; want %v", got, want)
	}

	var called bool
	for k := range set.Keys() {
		if k != key {
			t.Errorf("yielded key: got %v; want %v", k, key)
		}
		called = true
	}
	if !called {
		t.Error("should have yielded the key")
	}
}

func TestNewSet(t *testing.T) {
	t.Parallel()

	k1 := &mockKey{
		alg: "RS256",
		kid: "k1",
	}
	k2 := &mockKey{
		alg: "RS256",
		kid: "k2",
	}
	k3 := &mockKey{
		alg: "RS256",
		kid: "k1", // Overwrites k1
	}

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		s := jwk.NewSet()
		if got, want := s.Len(), 0; got != want {
			t.Errorf("got size %d; want %d", got, want)
		}
	})

	t.Run("singleton", func(t *testing.T) {
		t.Parallel()
		s := jwk.NewSet(k1)
		if got, want := s.Len(), 1; got != want {
			t.Errorf("got size %d; want %d", got, want)
		}
	})

	t.Run("multiple", func(t *testing.T) {
		t.Parallel()
		s := jwk.NewSet(k1, k2)
		if got, want := s.Len(), 2; got != want {
			t.Errorf("size: got %d; want %d", got, want)
		}
		if got := s.Find(mockHint{alg: "RS256", kid: "k2"}); got != k2 {
			t.Errorf("found key: got %v; want %v", got, k2)
		}
	})

	t.Run("overwrite", func(t *testing.T) {
		t.Parallel()
		s := jwk.NewSet(k1, k3)
		if got, want := s.Len(), 2; got != want {
			t.Errorf("size: got %d; want %d", got, want)
		}
		if got := s.Find(mockHint{alg: "RS256", kid: "k1"}); got != k3 {
			t.Errorf("found key: got %v; want %v", got, k3)
		}
	})

	t.Run("sorting", func(t *testing.T) {
		t.Parallel()
		s := jwk.NewSet(k2, k1)
		var order []string
		for k := range s.Keys() {
			order = append(order, k.KeyID())
		}
		if len(order) != 2 || order[0] != "k1" || order[1] != "k2" {
			t.Errorf("got order %v; want [k1 k2]", order)
		}
	})
}

func TestSingletonSet_Find(t *testing.T) {
	t.Parallel()

	key := &mockKey{
		alg: "RS256",
		kid: "key-123",
	}

	tests := []struct {
		name      string
		hint      mockHint
		wantFound bool
	}{
		{
			name: "exact match on kid",
			hint: mockHint{
				alg: "RS256",
				kid: "key-123",
			},
			wantFound: true,
		},
		{
			name: "algorithm mismatch returns nil",
			hint: mockHint{
				alg: "ES256",
				kid: "key-123",
			},
			wantFound: false,
		},
		{
			name: "wrong kid returns nil",
			hint: mockHint{
				alg: "RS256",
				kid: "wrong-id",
			},
			wantFound: false,
		},
		{
			name: "empty hint returns nil",
			hint: mockHint{
				alg: "RS256",
			},
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			set := jwk.Singleton(key)
			got := set.Find(tt.hint)

			if tt.wantFound {
				if got != key {
					t.Errorf("got %v; want the original key", got)
				}
			} else if got != nil {
				t.Errorf("got %v; want nil", got)
			}
		})
	}

	t.Run("nil hint returns nil", func(t *testing.T) {
		t.Parallel()
		set := jwk.Singleton(key)
		if got := set.Find(nil); got != nil {
			t.Errorf("got %v; want nil", got)
		}
	})

	// A key with an empty kid must be found by an empty-kid hint, matching
	// the behavior of the multi-key set implementation.
	t.Run("empty kid matches empty hint", func(t *testing.T) {
		t.Parallel()
		anon := &mockKey{alg: "RS256", kid: ""}
		set := jwk.Singleton(anon)
		if got := set.Find(mockHint{alg: "RS256", kid: ""}); got != anon {
			t.Errorf("got %v; want the original key", got)
		}
	})
}

func TestBuilder(t *testing.T) {
	t.Parallel()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key generation: should not have returned an error: %v", err)
	}
	id := "test-id"

	t.Run("build", func(t *testing.T) {
		t.Parallel()
		v := jwk.NewKey(jwa.ES256, id, &k.PublicKey)
		if got, want := v.KeyID(), id; got != want {
			t.Errorf("key id: got %q; want %q", got, want)
		}
		if got, want := v.Algorithm(), "ES256"; got != want {
			t.Errorf("algorithm: got %q; want %q", got, want)
		}
	})

	t.Run("build pair", func(t *testing.T) {
		t.Parallel()
		p := jwk.NewKeyPair(jwa.ES256, id, sign.From(k))
		if got, want := p.KeyID(), id; got != want {
			t.Errorf("key id: got %q; want %q", got, want)
		}

		msg := []byte("payload")
		sig, err := p.Sign(context.Background(), msg)
		if err != nil {
			t.Fatalf("signing: should not have returned an error: %v", err)
		}
		if !p.Verify(msg, sig) {
			t.Error("verification: got false; want true")
		}
	})
	t.Run("empty kid", func(t *testing.T) {
		t.Parallel()
		v := jwk.NewKey(jwa.ES256, "", &k.PublicKey)
		if got, want := v.KeyID(), ""; got != want {
			t.Errorf("key: got %q; want %q", got, want)
		}

		p := jwk.NewKeyPair(jwa.ES256, "", sign.From(k))
		if got, want := p.KeyID(), ""; got != want {
			t.Errorf("key pair: got %q; want %q", got, want)
		}
	})

	t.Run("type mismatch returns nil", func(t *testing.T) {
		t.Parallel()
		rs, _ := rsa.GenerateKey(rand.Reader, 2048)
		if p := jwk.NewKeyPair(jwa.ES256, "x", sign.From(rs)); p != nil {
			t.Error("should have returned nil for an RS signer with ES256")
		}
		if p := jwk.NewKeyPair(jwa.RS256, "x", sign.From(k)); p != nil {
			t.Error("should have returned nil for an EC signer with RS256")
		}
	})
}

func TestThumbprint(t *testing.T) {
	t.Parallel()

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key generation: should not have returned an error: %v", err)
	}

	kid, err := jwk.Thumbprint(&k.PublicKey)
	if err != nil {
		t.Fatalf("on first call: should not have returned an error: %v", err)
	}
	if kid == "" {
		t.Error("got empty thumbprint; want non-empty")
	}

	kid2, err := jwk.Thumbprint(&k.PublicKey)
	if err != nil {
		t.Fatalf("on second call: should not have returned an error: %v", err)
	}
	if kid != kid2 {
		t.Errorf("should be deterministic: got %q and %q", kid, kid2)
	}
}

func TestGenerate(t *testing.T) {
	t.Parallel()

	kp, err := jwk.Generate(jwa.ES256)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if kp == nil {
		t.Fatal("got nil key pair; want non-nil")
	}

	if kp.Algorithm() != "ES256" {
		t.Errorf("algorithm: got %q; want %q", kp.Algorithm(), "ES256")
	}

	if kp.KeyID() == "" {
		t.Error("got empty key id; want non-empty")
	}

	msg := []byte("payload")
	sig, err := kp.Sign(context.Background(), msg)
	if err != nil {
		t.Fatalf("signing: should not have returned an error: %v", err)
	}
	if !kp.Verify(msg, sig) {
		t.Error("verification: got false; want true")
	}
}

func TestGenerate_MLDSA(t *testing.T) {
	t.Parallel()

	kp, err := jwk.Generate(jwa.MLDSA44)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if kp.Algorithm() != "ML-DSA-44" {
		t.Errorf("algorithm: got %q; want %q", kp.Algorithm(), "ML-DSA-44")
	}
	if kp.KeyID() == "" {
		t.Error("got empty key id; want non-empty")
	}

	msg := []byte("payload")
	sig, err := kp.Sign(context.Background(), msg)
	if err != nil {
		t.Fatalf("signing: should not have returned an error: %v", err)
	}
	if !kp.Verify(msg, sig) {
		t.Error("verification: got false; want true")
	}

	// The public key must survive a JWK round-trip.
	encoded, err := jwk.Write(kp)
	if err != nil {
		t.Fatalf("encoding: should not have returned an error: %v", err)
	}
	parsed, err := jwk.Parse(encoded)
	if err != nil {
		t.Fatalf("re-parsing: should not have returned an error: %v", err)
	}
	if !parsed.Verify(msg, sig) {
		t.Error("round-trip verification: got false; want true")
	}
}

func TestNewKeyPairFor(t *testing.T) {
	t.Parallel()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key generation: should not have returned an error: %v", err)
	}

	t.Run("known algorithm", func(t *testing.T) {
		t.Parallel()
		kp, err := jwk.NewKeyPairFor("ES256", "kid-1", sign.From(k))
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if got, want := kp.Algorithm(), "ES256"; got != want {
			t.Errorf("algorithm: got %q; want %q", got, want)
		}
	})

	t.Run("unknown algorithm", func(t *testing.T) {
		t.Parallel()
		if _, err := jwk.NewKeyPairFor(
			"XY99",
			"kid-1",
			sign.From(k),
		); err == nil {
			t.Error("should have returned an error")
		}
	})

	t.Run("type mismatch", func(t *testing.T) {
		t.Parallel()
		if _, err := jwk.NewKeyPairFor(
			"RS256",
			"kid-1",
			sign.From(k),
		); err == nil {
			t.Error("should have returned an error")
		}
	})
}

func TestHandler(t *testing.T) {
	t.Parallel()

	key := &mockKey{
		alg: "RS256",
		kid: "test-kid",
		mat: &rsa.PublicKey{N: big.NewInt(123), E: 65537},
	}
	s := jwk.Singleton(key)

	r := router.New()
	r.HandleFunc("GET /jwks", jwk.Handler(s))

	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if exp, act := http.StatusOK, rec.Code; exp != act {
		t.Errorf("status code: got %d; want %d", act, exp)
	}

	if exp, act := jwk.MediaTypeSet,
		rec.Header().Get("Content-Type"); exp != act {
		t.Errorf("content type: got %s; want %s", act, exp)
	}

	set, err := jwk.ParseSet(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parsing response: should not have returned an error: %v", err)
	}

	if exp, act := 1, set.Len(); exp != act {
		t.Errorf("set size: got %d; want %d", act, exp)
	}
}
