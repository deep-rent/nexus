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

	"github.com/deep-rent/nexus/jose/jwa"
)

var mockMsg = []byte("payload")

func TestAlgorithm_RSASignVerify(t *testing.T) {
	t.Parallel()

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	tests := []struct {
		name string
		a    jwa.Algorithm[*rsa.PublicKey]
	}{
		{"RS256", jwa.RS256},
		{"RS384", jwa.RS384},
		{"RS512", jwa.RS512},
		{"PS256", jwa.PS256},
		{"PS384", jwa.PS384},
		{"PS512", jwa.PS512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sig, err := tt.a.Sign(k, mockMsg)
			if err != nil {
				t.Fatalf("%s.Sign() error = %v", tt.name, err)
			}
			if !tt.a.Verify(&k.PublicKey, mockMsg, sig) {
				t.Errorf("%s.Verify() = false; want true", tt.name)
			}
		})
	}
}

func TestAlgorithm_ECDSASignVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		a     jwa.Algorithm[*ecdsa.PublicKey]
		curve elliptic.Curve
	}{
		{"ES256", jwa.ES256, elliptic.P256()},
		{"ES384", jwa.ES384, elliptic.P384()},
		{"ES512", jwa.ES512, elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			k, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("ecdsa.GenerateKey() error = %v", err)
			}

			sig, err := tt.a.Sign(k, mockMsg)
			if err != nil {
				t.Fatalf("%s.Sign() error = %v", tt.name, err)
			}
			if !tt.a.Verify(&k.PublicKey, mockMsg, sig) {
				t.Errorf("%s.Verify() = false; want true", tt.name)
			}
		})
	}
}

func TestAlgorithm_EdDSASignVerify(t *testing.T) {
	t.Parallel()

	t.Run("ed25519", func(t *testing.T) {
		t.Parallel()
		pub, prv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey() error = %v", err)
		}

		sig, err := jwa.EdDSA.Sign(prv, mockMsg)
		if err != nil {
			t.Fatalf("EdDSA.Sign(Ed25519) error = %v", err)
		}
		if !jwa.EdDSA.Verify(pub, mockMsg, sig) {
			t.Errorf("EdDSA.Verify(Ed25519) = false; want true")
		}
	})

	t.Run("ed448", func(t *testing.T) {
		t.Parallel()
		pub, prv, err := ed448.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed448.GenerateKey() error = %v", err)
		}

		sig, err := jwa.EdDSA.Sign(prv, mockMsg)
		if err != nil {
			t.Fatalf("EdDSA.Sign(Ed448) error = %v", err)
		}
		if !jwa.EdDSA.Verify(pub, mockMsg, sig) {
			t.Errorf("EdDSA.Verify(Ed448) = false; want true")
		}
	})
}
