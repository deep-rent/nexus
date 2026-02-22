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

package jwa_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deep-rent/nexus/jose/jwa"
)

var msg = []byte("payload")

func TestRSA(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		n string
		a jwa.Algorithm[*rsa.PublicKey]
	}{
		{"RS256", jwa.RS256},
		{"RS384", jwa.RS384},
		{"RS512", jwa.RS512},
		{"PS256", jwa.PS256},
		{"PS384", jwa.PS384},
		{"PS512", jwa.PS512},
	}

	for _, tc := range tests {
		t.Run(tc.n, func(t *testing.T) {
			sig, err := tc.a.Sign(k, msg)
			require.NoError(t, err)
			assert.True(t, tc.a.Verify(&k.PublicKey, msg, sig))
		})
	}
}

func TestECDSA(t *testing.T) {
	tests := []struct {
		n string
		a jwa.Algorithm[*ecdsa.PublicKey]
		c elliptic.Curve
	}{
		{"ES256", jwa.ES256, elliptic.P256()},
		{"ES384", jwa.ES384, elliptic.P384()},
		{"ES512", jwa.ES512, elliptic.P521()},
	}

	for _, tc := range tests {
		t.Run(tc.n, func(t *testing.T) {
			k, err := ecdsa.GenerateKey(tc.c, rand.Reader)
			require.NoError(t, err)

			sig, err := tc.a.Sign(k, msg)
			require.NoError(t, err)
			assert.True(t, tc.a.Verify(&k.PublicKey, msg, sig))
		})
	}
}

func TestEdDSA(t *testing.T) {
	t.Run("Ed25519", func(t *testing.T) {
		pub, prv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		sig, err := jwa.EdDSA.Sign(prv, msg)
		require.NoError(t, err)
		assert.True(t, jwa.EdDSA.Verify(pub, msg, sig))
	})

	t.Run("Ed448", func(t *testing.T) {
		pub, prv, err := ed448.GenerateKey(rand.Reader)
		require.NoError(t, err)

		sig, err := jwa.EdDSA.Sign(prv, msg)
		require.NoError(t, err)
		assert.True(t, jwa.EdDSA.Verify(pub, msg, sig))
	})
}
