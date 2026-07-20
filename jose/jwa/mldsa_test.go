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
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"testing"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/sign"
)

func TestAlgorithm_MLDSASignVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		a      jwa.Algorithm[*mldsa.PublicKey]
		params mldsa.Parameters
	}{
		{"ML-DSA-44", jwa.MLDSA44, mldsa.MLDSA44()},
		{"ML-DSA-65", jwa.MLDSA65, mldsa.MLDSA65()},
		{"ML-DSA-87", jwa.MLDSA87, mldsa.MLDSA87()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			k, err := mldsa.GenerateKey(tt.params)
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
			if !tt.a.Verify(k.PublicKey(), mockMsg, sig) {
				t.Error("verification: got false; want true")
			}
		})
	}
}

func TestAlgorithm_MLDSAParameterMismatch(t *testing.T) {
	t.Parallel()

	k, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("key generation: should not have returned an error: %v", err)
	}

	sig, err := jwa.MLDSA65.Sign(t.Context(), sign.From(k), mockMsg)
	if err != nil {
		t.Fatalf("signing: should not have returned an error: %v", err)
	}
	if jwa.MLDSA44.Verify(k.PublicKey(), mockMsg, sig) {
		t.Error("should have rejected a key with a mismatched parameter set")
	}

	if _, err := jwa.MLDSA44.Sign(
		t.Context(),
		sign.From(k),
		mockMsg,
	); err == nil {
		t.Error("signing with a mismatched parameter set should have failed")
	}
}

func TestAlgorithm_MLDSASignWrongKeyType(t *testing.T) {
	t.Parallel()

	_, prv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation: should not have returned an error: %v", err)
	}

	_, err = jwa.MLDSA44.Sign(t.Context(), sign.From(prv), mockMsg)
	if err == nil {
		t.Error("signing with a non-ML-DSA key should have failed")
	}
}
