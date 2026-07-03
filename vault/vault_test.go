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
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"os"
	"path/filepath"
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

type configItem struct {
	Kid string `json:"kid"`
	Pem string `json:"pem"`
	Alg string `json:"alg"`
}

func encodePEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block))
}

func TestLoad(t *testing.T) {
	t.Parallel()

	rsaSigner, err := jwa.RS256.Generate()
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	ecdsaSigner, err := jwa.ES256.Generate()
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	items := []configItem{
		{
			Kid: "rsa-key-1",
			Alg: "RS256",
			Pem: encodePEM(t, rsaSigner),
		},
		{
			Kid: "ecdsa-key-1",
			Alg: "ES256",
			Pem: encodePEM(t, ecdsaSigner),
		},
	}

	configData, err := json.Marshal(items)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	v, err := vault.Load(configData, rotor.Sequential)
	if err != nil {
		t.Fatalf("unexpected error loading vault: %v", err)
	}

	keys := v.Keys()
	if exp, act := 2, keys.Len(); exp != act {
		t.Errorf("expected %d keys, got %d", exp, act)
	}

	next := v.Next()
	if next == nil {
		t.Fatal("v.Next() returned nil")
	}

	if act := next.KeyID(); act != "rsa-key-1" && act != "ecdsa-key-1" {
		t.Errorf("unexpected next key ID: %s", act)
	}
}

func TestLoadFile(t *testing.T) {
	t.Parallel()

	signer, err := jwa.ES256.Generate()
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	items := []configItem{
		{
			Kid: "ecdsa-file-1",
			Alg: "ES256",
			Pem: encodePEM(t, signer),
		},
	}

	config, err := json.Marshal(items)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(path, config, 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	v, err := vault.LoadFile(path, rotor.Sequential)
	if err != nil {
		t.Fatalf("unexpected error loading from file: %v", err)
	}

	if exp, act := 1, v.Keys().Len(); exp != act {
		t.Errorf("expected %d keys, got %d", exp, act)
	}
}
