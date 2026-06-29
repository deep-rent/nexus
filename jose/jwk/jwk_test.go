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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/signer"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
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
		t.Fatalf("os.ReadFile(%q) error = %v", name, err)
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
			"q3TlIAMpJF6VoTuJuaLZDUzXbFV-k7kLhAi5gYmV37Y",
			"Ed448.json",
		},
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
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			t.Parallel()
			in := readTestFile(t, tt.src)

			key1, err := jwk.Parse(in)
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", tt.src, err)
			}
			if got, want := key1.Algorithm(), tt.alg; got != want {
				t.Errorf("key1.Algorithm() = %q; want %q", got, want)
			}
			if got, want := key1.KeyID(), tt.kid; got != want {
				t.Errorf("key1.KeyID() = %q; want %q", got, want)
			}

			encoded, err := jwk.Write(key1)
			if err != nil {
				t.Fatalf("Write() error = %v", err)
			}

			key2, err := jwk.Parse(encoded)
			if err != nil {
				t.Fatalf("Parse(encoded) error = %v", err)
			}
			if got, want := key2.Algorithm(), key1.Algorithm(); got != want {
				t.Errorf("key2.Algorithm() = %q; want %q", got, want)
			}
			if got, want := key2.KeyID(), key1.KeyID(); got != want {
				t.Errorf("key2.KeyID() = %q; want %q", got, want)
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := readTestFile(t, tt.file)
			if _, err := jwk.Parse(in); err == nil {
				t.Errorf("Parse(%q) expected error; got nil", tt.file)
			}
		})
	}
}

func TestParseSet(t *testing.T) {
	t.Parallel()

	in := readTestFile(t, "set.json")

	set, err := jwk.ParseSet(in)
	if err != nil {
		t.Fatalf("ParseSet() error = %v", err)
	}
	if got, want := set.Len(), 11; got != want {
		t.Errorf("set.Len() = %d; want %d", got, want)
	}

	encoded, err := jwk.WriteSet(set)
	if err != nil {
		t.Fatalf("WriteSet() error = %v", err)
	}

	set2, err := jwk.ParseSet(encoded)
	if err != nil {
		t.Fatalf("ParseSet(encoded) error = %v", err)
	}
	if got, want := set2.Len(), set.Len(); got != want {
		t.Errorf("set2.Len() = %d; want %d", got, want)
	}

	for k := range set.Keys() {
		found := set2.Find(k)
		if found == nil {
			t.Errorf("key %q lost during round-trip", k.KeyID())
			continue
		}
		if got, want := found.KeyID(), k.KeyID(); got != want {
			t.Errorf("found.KeyID() = %q; want %q", got, want)
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
				t.Errorf("ParseSet(%q) expected error; got nil", tt.file)
			}
		})
	}
}

func TestParseSet_PartialSuccess(t *testing.T) {
	t.Parallel()

	set, err := jwk.ParseSet(readTestFile(t, "set_partial.json"))
	if err == nil {
		t.Errorf("ParseSet(partial) expected error; got nil")
	}
	if got, want := set.Len(), 2; got != want {
		t.Errorf("set.Len() = %d; want %d", got, want)
	}

	k1 := set.Find(&mockKey{alg: "ES256", kid: "valid-1"})
	if k1 == nil {
		t.Errorf("could not find valid-1")
	}
	k2 := set.Find(&mockKey{alg: "ES512", kid: "valid-2"})
	if k2 == nil {
		t.Errorf("could not find valid-2")
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
				t.Fatalf("Write() expected error; got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Write() error = %q; want it to contain %q",
					err, tt.wantErr)
			}
		})
	}
}

func TestWriteSet_Errors(t *testing.T) {
	t.Parallel()

	s := jwk.Singleton(&mockKey{alg: "XY99"})
	if _, err := jwk.WriteSet(s); err == nil {
		t.Errorf("WriteSet() expected error; got nil")
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
		t.Errorf("set.Len() = %d; want %d", got, want)
	}
	if got, want := set.Find(key), key; got != want {
		t.Errorf("set.Find() = %v; want %v", got, want)
	}

	var called bool
	for k := range set.Keys() {
		if k != key {
			t.Errorf("set.Keys() yielded %v; want %v", k, key)
		}
		called = true
	}
	if !called {
		t.Errorf("set.Keys() did not yield the key")
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
			t.Errorf("Len() = %d; want %d", got, want)
		}
	})

	t.Run("singleton", func(t *testing.T) {
		t.Parallel()
		s := jwk.NewSet(k1)
		if got, want := s.Len(), 1; got != want {
			t.Errorf("Len() = %d; want %d", got, want)
		}
	})

	t.Run("multiple", func(t *testing.T) {
		t.Parallel()
		s := jwk.NewSet(k1, k2)
		if got, want := s.Len(), 2; got != want {
			t.Errorf("Len() = %d; want %d", got, want)
		}
		if got := s.Find(mockHint{alg: "RS256", kid: "k2"}); got != k2 {
			t.Errorf("Find(k2) = %v; want %v", got, k2)
		}
	})

	t.Run("overwrite", func(t *testing.T) {
		t.Parallel()
		s := jwk.NewSet(k1, k3)
		if got, want := s.Len(), 2; got != want {
			t.Errorf("Len() = %d; want %d", got, want)
		}
		if got := s.Find(mockHint{alg: "RS256", kid: "k1"}); got != k3 {
			t.Errorf("Find(k1) = %v; want %v", got, k3)
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
			t.Errorf("Keys() order = %v; want [k1 k2]", order)
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
					t.Errorf("Find() = %v; want original key", got)
				}
			} else if got != nil {
				t.Errorf("Find() = %v; want nil", got)
			}
		})
	}
}

func TestBuilder(t *testing.T) {
	t.Parallel()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	id := "test-id"

	t.Run("build", func(t *testing.T) {
		t.Parallel()
		v := jwk.NewKeyBuilder(jwa.ES256).WithKeyID(id).Build(&k.PublicKey)
		if got, want := v.KeyID(), id; got != want {
			t.Errorf("v.KeyID() = %q; want %q", got, want)
		}
		if got, want := v.Algorithm(), "ES256"; got != want {
			t.Errorf("v.Algorithm() = %q; want %q", got, want)
		}
	})

	t.Run("build pair", func(t *testing.T) {
		t.Parallel()
		p := jwk.NewKeyBuilder(jwa.ES256).WithKeyID(id).BuildPair(signer.From(k))
		if got, want := p.KeyID(), id; got != want {
			t.Errorf("p.KeyID() = %q; want %q", got, want)
		}

		msg := []byte("payload")
		sig, err := p.Sign(context.Background(), msg)
		if err != nil {
			t.Fatalf("p.Sign() error = %v", err)
		}
		if !p.Verify(msg, sig) {
			t.Errorf("p.Verify() = false; want true")
		}
	})
}

func TestBuilder_Panic(t *testing.T) {
	t.Parallel()

	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name string
		call func()
	}{
		{
			name: "unidentified key",
			call: func() {
				jwk.NewKeyBuilder(jwa.ES256).Build(&ec.PublicKey)
			},
		},
		{
			name: "unidentified key pair",
			call: func() {
				jwk.NewKeyBuilder(jwa.ES256).BuildPair(signer.From(ec))
			},
		},
		{
			name: "incompatible key type 1",
			call: func() {
				jwk.NewKeyBuilder(jwa.ES256).WithKeyID("x").BuildPair(signer.From(rs))
			},
		},
		{
			name: "incompatible key type 2",
			call: func() {
				jwk.NewKeyBuilder(jwa.RS256).WithKeyID("x").BuildPair(signer.From(ec))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("Expected panic for %q", tt.name)
				}
			}()
			tt.call()
		})
	}
}
