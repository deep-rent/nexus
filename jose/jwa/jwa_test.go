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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"testing"

	"github.com/deep-rent/nexus/sign"

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
			sig, err := tt.a.Sign(t.Context(), sign.From(k), mockMsg)
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

			sig, err := tt.a.Sign(t.Context(), sign.From(k), mockMsg)
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

		sig, err := jwa.EdDSA.Sign(t.Context(), sign.From(prv), mockMsg)
		if err != nil {
			t.Fatalf("EdDSA.Sign(Ed25519) error = %v", err)
		}
		if !jwa.EdDSA.Verify(pub, mockMsg, sig) {
			t.Errorf("EdDSA.Verify(Ed25519) = false; want true")
		}
	})
}

type mockSigner struct {
	signer crypto.Signer
	passed bool
}

func (m *mockSigner) Public() crypto.PublicKey { return m.signer.Public() }

func (m *mockSigner) Sign(
	ctx context.Context,
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) (signature []byte, err error) {
	if ctx != nil {
		m.passed = true
	}
	return m.signer.Sign(rand, digest, opts)
}

var _ sign.Signer = (*mockSigner)(nil)

func TestAlgorithm_Sign(t *testing.T) {
	t.Parallel()

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	mock := &mockSigner{signer: k}
	ctx := t.Context()

	_, err = jwa.RS256.Sign(ctx, mock, mockMsg)
	if err != nil {
		t.Fatalf("RS256.Sign() error = %v", err)
	}
	if !mock.passed {
		t.Errorf("RS256 did not propagate context")
	}

	esKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockES := &mockSigner{signer: esKey}
	_, _ = jwa.ES256.Sign(ctx, mockES, mockMsg)
	if !mockES.passed {
		t.Errorf("ES256 did not propagate context")
	}

	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	mockEd := &mockSigner{signer: edKey}
	_, _ = jwa.EdDSA.Sign(ctx, mockEd, mockMsg)
	if !mockEd.passed {
		t.Errorf("EdDSA did not propagate context")
	}
}
