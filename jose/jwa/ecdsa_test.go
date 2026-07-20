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
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"io"
	"math/big"
	"testing"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/sign"
)

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
				t.Fatalf(
					"key generation: should not have returned an error: %v",
					err,
				)
			}

			sig, err := tt.a.Sign(t.Context(), sign.From(k), mockMsg)
			if err != nil {
				t.Fatalf("signing: should not have returned an error: %v", err)
			}
			if !tt.a.Verify(&k.PublicKey, mockMsg, sig) {
				t.Error("verification: got false; want true")
			}
		})
	}
}

func TestAlgorithm_ECDSAPaddingPanic(t *testing.T) {
	t.Parallel()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key generation: should not have returned an error: %v", err)
	}

	// 261 bits, P-256 is 256 bits max
	exceed := new(big.Int).Lsh(big.NewInt(1), 260)
	concat := struct{ R, S *big.Int }{R: exceed, S: exceed}
	der, err := asn1.Marshal(concat)
	if err != nil {
		t.Fatalf("marshalling: should not have returned an error: %v", err)
	}

	mock := &mockECDSASigner{pub: &k.PublicKey, sig: der}
	_, err = jwa.ES256.Sign(t.Context(), mock, mockMsg)
	if err == nil {
		t.Error("should have returned an error")
	}
}

type mockECDSASigner struct {
	pub *ecdsa.PublicKey
	sig []byte
}

func (m *mockECDSASigner) Public() crypto.PublicKey { return m.pub }

func (m *mockECDSASigner) Sign(
	ctx context.Context,
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) ([]byte, error) {
	return m.sig, nil
}
