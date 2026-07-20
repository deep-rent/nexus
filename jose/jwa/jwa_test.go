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

	"crypto/mldsa"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/sign"
)

var mockMsg = []byte("payload")

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
		t.Fatalf("key generation: should not have returned an error: %v", err)
	}

	mock := &mockSigner{signer: k}
	ctx := t.Context()

	_, err = jwa.RS256.Sign(ctx, mock, mockMsg)
	if err != nil {
		t.Fatalf("RS256 signing: should not have returned an error: %v", err)
	}
	if !mock.passed {
		t.Error("RS256 should have propagated the context")
	}

	esKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockES := &mockSigner{signer: esKey}
	_, _ = jwa.ES256.Sign(ctx, mockES, mockMsg)
	if !mockES.passed {
		t.Error("ES256 should have propagated the context")
	}

	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	mockEd := &mockSigner{signer: edKey}
	_, _ = jwa.EdDSA.Sign(ctx, mockEd, mockMsg)
	if !mockEd.passed {
		t.Error("EdDSA should have propagated the context")
	}

	mlKey, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	mockML := &mockSigner{signer: mlKey}
	_, _ = jwa.MLDSA44.Sign(ctx, mockML, mockMsg)
	if !mockML.passed {
		t.Error("ML-DSA-44 should have propagated the context")
	}
}

func TestAlgorithm_Generate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		gen  func() (crypto.Signer, error)
	}{
		{"RS256", jwa.RS256.Generate},
		{"RS384", jwa.RS384.Generate},
		{"RS512", jwa.RS512.Generate},
		{"PS256", jwa.PS256.Generate},
		{"PS384", jwa.PS384.Generate},
		{"PS512", jwa.PS512.Generate},
		{"ES256", jwa.ES256.Generate},
		{"ES384", jwa.ES384.Generate},
		{"ES512", jwa.ES512.Generate},
		{"EdDSA", jwa.EdDSA.Generate},
		{"ML-DSA-44", jwa.MLDSA44.Generate},
		{"ML-DSA-65", jwa.MLDSA65.Generate},
		{"ML-DSA-87", jwa.MLDSA87.Generate},
	}

	for _, tt := range tests {
		name := tt.name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s, err := tt.gen()
			if err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}
			if s == nil {
				t.Fatal("got nil signer; want non-nil")
			}
			if s.Public() == nil {
				t.Error("got nil public key; want non-nil")
			}
		})
	}
}
