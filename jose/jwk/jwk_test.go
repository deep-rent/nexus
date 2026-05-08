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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
)

type mockKey struct {
	kid string
	alg string
	x5t string
	mat any
}

func (k *mockKey) Algorithm() string       { return k.alg }
func (k *mockKey) KeyID() string           { return k.kid }
func (k *mockKey) Thumbprint() string      { return k.x5t }
func (k *mockKey) Verify(_, _ []byte) bool { return true }
func (k *mockKey) Material() any           { return k.mat }

var _ jwk.Key = (*mockKey)(nil)

type mockHint struct {
	alg string
	kid string
	x5t string
}

func (h mockHint) Algorithm() string  { return h.alg }
func (h mockHint) KeyID() string      { return h.kid }
func (h mockHint) Thumbprint() string { return h.x5t }

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
		x5t string
		src string
	}{
		{
			"EdDSA",
			"q3TlIAMpJF6VoTuJuaLZDUzXbFV-k7kLhAi5gYmV37Y",
			"6fdfc2b56f326d45f47cdddd0a7c6a378ad92241d3183e2479be28604aa4f7a7",
			"Ed448.json",
		},
		{
			"EdDSA",
			"P6rOVdsYhY_b0VzNdk568I9tYrAnBw-WGgsMZ2zMOvA",
			"381004f8c7897d5ab2198c9cc2ab81a831f5d0827472a728c0e991e0b44da189",
			"Ed25519.json",
		},
		{
			"ES256",
			"chs_bZZOVng98tfs-pQRig3RTaXszdcZ0WsoyWORzDQ",
			"8ae7b0b40e5abe8670d6c50500625957e824a6aad1ffc60c7cd5a082bf02cdba",
			"ES256.json",
		},
		{
			"ES384",
			"HCgaZlHgiGkHQ9f3Q2FWYs_NtZzQsLWaii8puMRbhhE",
			"155477264a68dd6aa13969ccbbaa88c93511ccc779b9119441059298c2eb2b27",
			"ES384.json",
		},
		{
			"ES512",
			"3xQ6MwN6aFYouSGZyqv9DYvst-CV_12M58EvjJ6wHQs",
			"036a6650cb354e6227e38bb10cecc56a4958cec5f30417cb7d8b44e5cede1dd5",
			"ES512.json",
		},
		{
			"PS256",
			"1iPDx07kLtDB6MeYwD451j-NUaZFv3QS4mFCCdIbaeQ",
			"0ddbbcbf7bf93b579e2bbb550ebb44400789c64dbceff20b603bfdf2688f152a",
			"PS256.json",
		},
		{
			"PS384",
			"5q0HzRnzOR2DivWMl4q2MpKXy8IdnfYMxc-c1s6Olhc",
			"a371ace0a34d95b88f0cade1607149aa9fadcc3abf942717b36c04f7c00bc124",
			"PS384.json",
		},
		{
			"PS512",
			"6f-mwTH8QRxXXZHP7teEem1uqkGFYGPKSDxOqXc3xzQ",
			"262e6fb460d5d124953cdb83b836025e351d18255add4e0c03ca9c0643e38319",
			"PS512.json",
		},
		{
			"RS256",
			"KO4ZegrzU_W1RcC89v05Ev3C2JXHC2aQKNo08ZSbnC4",
			"72b885d85336f6b4ef73b1df7125ef8f416e63a00d6167aeb2dcaac3e2ce1446",
			"RS256.json",
		},
		{
			"RS384",
			"g1jIq7AVMQRV3YHbLk3tJfHUJfwgVuzPzkMK3R1K_GU",
			"ecd720239f966c6ef8e5212be757302e67b6435def75bed346bbdb183f623d29",
			"RS384.json",
		},
		{
			"RS512",
			"DYHSGgm9DBjiFYkciaL3lFjKDPJQc0BO6nS7IacanVU",
			"f23401b9e029adf752b1ea06b8e02020fb26fe96bf2f885d9c7f00c5ba5ce67e",
			"RS512.json",
		},
		{
			"ES256",
			"",
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
			if got, want := key1.Thumbprint(), tt.x5t; got != want {
				t.Errorf("key1.Thumbprint() = %q; want %q", got, want)
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
			if got, want := key2.Thumbprint(), key1.Thumbprint(); got != want {
				t.Errorf("key2.Thumbprint() = %q; want %q", got, want)
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
		{"duplicate thumbprint", "duplicate_thumbprint.json"},
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
		x5t: "x5t",
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

func TestSingletonSet_Find(t *testing.T) {
	t.Parallel()

	key := &mockKey{
		alg: "RS256",
		kid: "key-123",
		x5t: "thumb-abc",
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
			name: "exact match on thumbprint",
			hint: mockHint{
				alg: "RS256",
				x5t: "thumb-abc",
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
			name: "wrong thumbprint returns nil",
			hint: mockHint{
				alg: "RS256",
				x5t: "wrong-thumb",
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
		p := jwk.NewKeyBuilder(jwa.ES256).WithKeyID(id).BuildPair(k)
		if got, want := p.KeyID(), id; got != want {
			t.Errorf("p.KeyID() = %q; want %q", got, want)
		}

		msg := []byte("payload")
		sig, err := p.Sign(msg)
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
				jwk.NewKeyBuilder(jwa.ES256).BuildPair(ec)
			},
		},
		{
			name: "incompatible key type 1",
			call: func() {
				jwk.NewKeyBuilder(jwa.ES256).WithKeyID("x").BuildPair(rs)
			},
		},
		{
			name: "incompatible key type 2",
			call: func() {
				jwk.NewKeyBuilder(jwa.RS256).WithKeyID("x").BuildPair(ec)
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
