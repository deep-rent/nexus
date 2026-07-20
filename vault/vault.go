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

// Package vault provides secure retrieval and rotation of cryptographic keys.
//
// Package vault manages a collection of JSON Web Keys (JWK) for signing and
// verification. The primary abstraction is the [Vault] interface, which
// abstracts away underlying key sources (like Kubernetes Secrets or KMS)
// and handles key rotation through a [rotor.Strategy].
//
// # Usage
//
// The vault is typically initialized from a JSON configuration array containing
// PEM-encoded keys, and can seamlessly integrate with HTTP routers to serve
// JWKS endpoints:
//
//   - [Load]: Parses a JSON configuration array to initialize a [Vault].
//   - [LoadFile]: Shortcut for loading data configuration from the filesystem.
//   - [Handler]: Creates an HTTP handler to serve the public keys as a JWK Set.
//
// Example:
//
//	v, err := vault.LoadFile("/etc/secrets/keys.json", rotor.Sequential)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	key := v.Next()
//	sig, err := key.Sign(context.Background(), payload)
//
//	r := router.New()
//	r.HandleFunc("GET /.well-known/jwks.json", vault.Handler(v))
package vault

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"

	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/rotor"
	"github.com/deep-rent/nexus/router"
	"github.com/deep-rent/nexus/sign"
)

// Vault represents a secure retrieval mechanism for cryptographic signing keys.
// It abstracts away the underlying implementation details of external sources
// like cluster-injected keys, KMS, HSM, or HashiCorp Vault.
type Vault interface {
	// Keys returns the set of all public keys for verification purposes.
	Keys() jwk.Set

	// Next retrieves the currently active [jwk.KeyPair] intended for signing
	// new tokens.
	Next() jwk.KeyPair
}

// vault is the default implementation of [Vault].
type vault struct {
	pub jwk.Set
	prv rotor.Rotor[jwk.KeyPair]
}

// New constructs a [Vault] using the provided set of cryptographic key pairs
// and rotation strategy. It panics if no keys are provided.
func New(keys []jwk.KeyPair, strategy rotor.Strategy) Vault {
	prv := rotor.New(strategy, keys)
	pub := make([]jwk.Key, 0, len(keys))
	for _, k := range keys {
		pub = append(pub, k)
	}
	return &vault{
		pub: jwk.NewSet(pub...),
		prv: prv,
	}
}

func (v *vault) Keys() jwk.Set     { return v.pub }
func (v *vault) Next() jwk.KeyPair { return v.prv.Next() }

var _ Vault = (*vault)(nil)

// Item represents a single cryptographic key configuration containing the key
// and algorithm identifiers, and PEM-encoded private key material.
type Item struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Pem string `json:"pem"`
}

// Items represents a collection of key configurations.
type Items []Item

// Save serializes a collection of key configurations into a JSON array,
// which can later be parsed by [Load].
func Save(items Items) ([]byte, error) {
	return json.Marshal(items)
}

// SaveFile is a convenience wrapper around [Save] that writes the configuration
// to the specified file path.
func SaveFile(path string, items Items) error {
	data, err := Save(items)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600) //nolint:gosec
}

// Load parses a JSON array of key configurations, where each item contains
// the key identifier, algorithm, and PEM-encoded private key material. It then
// uses these to construct a [Vault] instance with the specified rotation
// strategy.
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

		signer, err := sign.Decode([]byte(item.Pem))
		if err != nil {
			return nil, fmt.Errorf(
				"failed to parse PEM for key %q: %w",
				item.Kid, err,
			)
		}
		key, err := jwk.NewKeyPairFor(item.Alg, item.Kid, signer)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to build key pair for key %q: %w",
				item.Kid, err,
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

// Handler creates a [router.Handler] that exposes the public keys of the
// [Vault] as a JSON Web Key Set (JWKS).
func Handler(v Vault) router.Handler {
	return jwk.Handler(v.Keys())
}
