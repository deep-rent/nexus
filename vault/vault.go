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

package vault

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/rotor"
	"github.com/deep-rent/nexus/router"
	"github.com/deep-rent/nexus/sign"
)

// Vault represents a secure retrieval mechanism for cryptographic signing keys.
// It abstracts away the underlying implementation details of external sources
// like KMS, HSM, or HashiCorp Vault.
type Vault interface {
	Keys() jwk.Set

	// Next retrieves the currently active [jwk.KeyPair] intended for signing
	// new tokens.
	Next() jwk.KeyPair
}

type vault struct {
	pub jwk.Set
	prv rotor.Rotor[jwk.KeyPair]
}

func New(keys []jwk.KeyPair, strategy rotor.Strategy) Vault {
	pub := make([]jwk.Key, 0, len(keys))
	for _, k := range keys {
		pub = append(pub, k)
	}
	prv := rotor.New(strategy, keys)
	return &vault{
		pub: jwk.NewSet(pub...),
		prv: prv,
	}
}

func (v *vault) Keys() jwk.Set     { return v.pub }
func (v *vault) Next() jwk.KeyPair { return v.prv.Next() }

var _ Vault = (*vault)(nil)

type Item struct {
	Kid string `json:"kid"`
	Pem string `json:"pem"`
	Alg string `json:"alg"`
}

type Items []Item

// Load parses a JSON array of configuration items, where each item contains
// a Key ID (kid), Algorithm (alg), and Private Key (pem) encoded in PEM format.
// It constructs a Vault instance with the specified rotation strategy.
func Load(config []byte, strategy rotor.Strategy) (Vault, error) {
	var items Items
	if err := json.Unmarshal(config, &items); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	keys := make([]jwk.KeyPair, 0, len(items))
	for _, item := range items {
		if item.Alg == "" || item.Kid == "" || item.Pem == "" {
			return nil, fmt.Errorf("invalid key item: %v", item)
		}

		signer, err := sign.Parse([]byte(item.Pem))
		if err != nil {
			return nil, fmt.Errorf(
				"failed to parse PEM for key %q: %w",
				item.Kid, err,
			)
		}
		key, err := newKeyPair(item.Alg, item.Kid, signer)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to build key pair for key %q: %w",
				item.Kid, err,
			)
		}
		if key == nil {
			return nil, fmt.Errorf(
				"public key type mismatch for key %q and algorithm %s",
				item.Kid, item.Alg,
			)
		}
		keys = append(keys, key)
	}

	if len(keys) == 0 {
		return nil, errors.New("no valid keys found in config")
	}

	return New(keys, strategy), nil
}

// LoadFile is a convenience wrapper around [Load] that reads the configuration
// from the specified file path. This is particularly useful for loading keys
// mounted from Kubernetes Secrets or ConfigMaps.
func LoadFile(path string, strategy rotor.Strategy) (Vault, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, err
	}
	return Load(data, strategy)
}

func newKeyPair(alg, kid string, signer sign.Signer) (jwk.KeyPair, error) {
	switch alg {
	case "RS256":
		return jwk.NewKeyPair(jwa.RS256, kid, signer), nil
	case "RS384":
		return jwk.NewKeyPair(jwa.RS384, kid, signer), nil
	case "RS512":
		return jwk.NewKeyPair(jwa.RS512, kid, signer), nil
	case "PS256":
		return jwk.NewKeyPair(jwa.PS256, kid, signer), nil
	case "PS384":
		return jwk.NewKeyPair(jwa.PS384, kid, signer), nil
	case "PS512":
		return jwk.NewKeyPair(jwa.PS512, kid, signer), nil
	case "ES256":
		return jwk.NewKeyPair(jwa.ES256, kid, signer), nil
	case "ES384":
		return jwk.NewKeyPair(jwa.ES384, kid, signer), nil
	case "ES512":
		return jwk.NewKeyPair(jwa.ES512, kid, signer), nil
	case "EdDSA":
		return jwk.NewKeyPair(jwa.EdDSA, kid, signer), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func Handler(v Vault) router.Handler {
	return jwk.Handler(v.Keys())
}
