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

package vault_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/rotor"
	"github.com/deep-rent/nexus/sign"
	"github.com/deep-rent/nexus/vault"
)

func generateKeyPair(t *testing.T, kid string) jwk.KeyPair {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return jwk.NewKeyPair(jwa.ES256, kid, sign.From(k))
}

func TestVault(t *testing.T) {
	t.Parallel()

	k1 := generateKeyPair(t, "key-1")
	k2 := generateKeyPair(t, "key-2")
	k3 := generateKeyPair(t, "key-3")

	keys := []jwk.KeyPair{k1, k2, k3}

	v := vault.New(keys, rotor.Sequential)

	t.Run("Keys", func(t *testing.T) {
		set := v.Keys()
		if got, want := set.Len(), 3; got != want {
			t.Errorf("Keys().Len() = %d; want %d", got, want)
		}

		for _, h := range keys {
			k := set.Find(h)
			if k == nil {
				t.Errorf("Keys() missing key with ID %q", h.KeyID())
			}
		}
	})

	t.Run("Next", func(t *testing.T) {
		if got, want := v.Next().KeyID(), "key-1"; got != want {
			t.Errorf("Next() = %q; want %q", got, want)
		}
		if got, want := v.Next().KeyID(), "key-2"; got != want {
			t.Errorf("Next() = %q; want %q", got, want)
		}
		if got, want := v.Next().KeyID(), "key-3"; got != want {
			t.Errorf("Next() = %q; want %q", got, want)
		}
		if got, want := v.Next().KeyID(), "key-1"; got != want {
			t.Errorf("Next() = %q; want %q", got, want)
		}
	})
}
