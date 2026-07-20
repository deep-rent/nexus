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
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/sign"
)

func TestAlgorithm_RSASignVerify(t *testing.T) {
	t.Parallel()

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key generation: should not have returned an error: %v", err)
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
				t.Fatalf("signing: should not have returned an error: %v", err)
			}
			if !tt.a.Verify(&k.PublicKey, mockMsg, sig) {
				t.Error("verification: got false; want true")
			}
		})
	}
}
