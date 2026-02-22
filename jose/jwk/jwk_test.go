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
	"testing"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockKey struct {
	kid string
	alg string
	x5t string
	mat any
}

func (k *mockKey) Algorithm() string           { return k.alg }
func (k *mockKey) KeyID() string               { return k.kid }
func (k *mockKey) Thumbprint() string          { return k.x5t }
func (k *mockKey) Verify(msg, sig []byte) bool { return true }
func (k *mockKey) Material() any               { return k.mat }

func TestParse(t *testing.T) {
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
	}

	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			in := read(t, tc.src)

			key1, err := jwk.Parse(in)
			require.NoError(t, err)
			require.Equal(t, tc.alg, key1.Algorithm())
			require.Equal(t, tc.kid, key1.KeyID())
			require.Equal(t, tc.x5t, key1.Thumbprint())

			encoded, err := jwk.Write(key1)
			require.NoError(t, err, "failed to write key")

			key2, err := jwk.Parse(encoded)
			require.NoError(t, err, "failed to re-parse key")
			assert.Equal(t, key1.Algorithm(), key2.Algorithm())
			assert.Equal(t, key1.KeyID(), key2.KeyID())
			assert.Equal(t, key1.Thumbprint(), key2.Thumbprint())
		})
	}
}

func TestParseError(t *testing.T) {
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
		{"invalid ECDSA point (not on curve)", "ecdsa_not_on_curve.json"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := read(t, tc.file)
			_, err := jwk.Parse(in)
			require.Error(t, err)
		})
	}
}

func TestParseSet(t *testing.T) {
	in := read(t, "set.json")

	set, err := jwk.ParseSet(in)
	require.NoError(t, err)
	require.Equal(t, 11, set.Len())

	encoded, err := jwk.WriteSet(set)
	require.NoError(t, err, "failed to write set")

	set2, err := jwk.ParseSet(encoded)
	require.NoError(t, err, "failed to re-parse set")

	assert.Equal(t, set.Len(), set2.Len())

	for k := range set.Keys() {
		found := set2.Find(k)
		require.NotNil(t, found, "key %s lost during round-trip", k.KeyID())
		assert.Equal(t, k.KeyID(), found.KeyID())
	}
}

func TestParseSetError(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{"duplicate key id", "duplicate_key_id.json"},
		{"duplicate thumbprint", "duplicate_thumbprint.json"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := read(t, tc.file)
			_, err := jwk.ParseSet(in)
			require.Error(t, err)
		})
	}
}

func TestParseSetPartialSuccess(t *testing.T) {
	set, err := jwk.ParseSet(read(t, "set_partial.json"))

	require.Error(t, err)
	assert.Equal(t, 2, set.Len())

	k1 := set.Find(&mockKey{alg: "ES256", kid: "valid-1"})
	assert.NotNil(t, k1)
	k2 := set.Find(&mockKey{alg: "ES512", kid: "valid-2"})
	assert.NotNil(t, k2)
}

func TestWriteErrors(t *testing.T) {
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jwk.Write(tc.key)
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}
func TestWriteSetErrors(t *testing.T) {
	s := jwk.Singleton(&mockKey{alg: "XY99"})

	_, err := jwk.WriteSet(s)
	require.Error(t, err)
	assert.ErrorContains(t, err, "unsupported algorithm")
}

func TestSingleton(t *testing.T) {
	key := &mockKey{
		kid: "kid",
		x5t: "x5t",
		alg: "alg",
	}
	set := jwk.Singleton(key)
	assert.Equal(t, 1, set.Len())
	assert.Equal(t, key, set.Find(key))
	called := false
	for k := range set.Keys() {
		assert.Equal(t, key, k)
		called = true
	}
	assert.True(t, called)
}

func TestBuilder(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	id := "test-id"

	t.Run("Build", func(t *testing.T) {
		v := jwk.NewKeyBuilder(jwa.ES256).WithKeyID(id).Build(&k.PublicKey)
		assert.Equal(t, id, v.KeyID())
		assert.Equal(t, "ES256", v.Algorithm())
	})

	t.Run("BuildPair", func(t *testing.T) {
		p := jwk.NewKeyBuilder(jwa.ES256).WithKeyID(id).BuildPair(k)
		assert.Equal(t, id, p.KeyID())

		msg := []byte("payload")
		sig, err := p.Sign(msg)
		require.NoError(t, err)
		assert.True(t, p.Verify(msg, sig))
	})
}

func TestBuilderPanic(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name string
		call func()
	}{
		{
			"unidentified key",
			func() {
				jwk.NewKeyBuilder(jwa.ES256).Build(&ec.PublicKey)
			},
		},
		{
			"unidentified key pair",
			func() {
				jwk.NewKeyBuilder(jwa.ES256).BuildPair(ec)
			},
		},
		{
			"incompatible key type 1",
			func() {
				jwk.NewKeyBuilder(jwa.ES256).WithKeyID("x").BuildPair(rs)
			},
		},
		{
			"incompatible key type 2",
			func() {
				jwk.NewKeyBuilder(jwa.RS256).WithKeyID("x").BuildPair(ec)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Panics(t, tc.call)
		})
	}
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return b
}
