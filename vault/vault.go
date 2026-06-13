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

// Package vault provides abstractions for securely retrieving and managing
// cryptographic signing keys (JSON Web Key Pairs) from various storage backends.
package vault

import (
	"context"
	"errors"
	"iter"
	"slices"

	"github.com/deep-rent/nexus/jose/jwk"
)

// ErrKeyNotFound is returned when a requested key cannot be found in the vault.
var ErrKeyNotFound = errors.New("key not found in vault")

// Vault represents a secure retrieval mechanism for cryptographic
// signing keys ([jwk.KeyPair]). It abstracts away the underlying implementation
// details of external sources like KMS, HSM, or HashiCorp Vault.
type Vault interface {
	// Keys returns an iterator over all valid [jwk.KeyPair]s managed by this vault.
	// This is useful for exposing public keys via a JSON Web Key Set (JWKS) endpoint.
	Keys(ctx context.Context) (iter.Seq[jwk.KeyPair], error)

	// Find retrieves a specific [jwk.KeyPair] matching the specified hint (e.g., Key ID).
	// It returns [ErrKeyNotFound] if no matching key is found.
	Find(ctx context.Context, hint jwk.Hint) (jwk.KeyPair, error)

	// Next retrieves the currently active [jwk.KeyPair] intended for signing
	// new tokens. It returns [ErrKeyNotFound] if the vault is empty.
	Next(ctx context.Context) (jwk.KeyPair, error)
}

// Store represents an external backend capable of securely supplying and managing signing keys.
type Store interface {
	// Load retrieves all available signing keys from the store, decrypting them using the provided KEK.
	// The implementation must return the keys such that the currently active signing key is the first element.
	Load(ctx context.Context, kek []byte) ([]jwk.KeyPair, error)

	// Revoke invalidates a key by its Key ID, preventing it from being returned in future Load calls
	// or used for signing/verification.
	Revoke(ctx context.Context, kid string) error

	// Generate creates a new key pair, encrypts it using the provided KEK, and stores it in the backend.
	// This key typically becomes the new active key.
	Generate(ctx context.Context, kek []byte) (jwk.KeyPair, error)

	// Add imports an existing key pair from PEM format, encrypts it using the provided KEK,
	// and stores it in the backend.
	Add(ctx context.Context, kek []byte, pemData []byte) (jwk.KeyPair, error)
}

// vault is the concrete implementation of [Vault]. It uses a [Store] to
// retrieve the key material on demand.
type vault struct {
	store Store
	kek   []byte
}

// New creates a new [Vault] backed by the provided [Store] and KEK.
func New(store Store, kek []byte) Vault {
	return &vault{
		store: store,
		kek:   kek,
	}
}

// Keys implements [Vault].
func (v *vault) Keys(ctx context.Context) (iter.Seq[jwk.KeyPair], error) {
	keys, err := v.store.Load(ctx, v.kek)
	if err != nil {
		return nil, err
	}
	return slices.Values(keys), nil
}

// Find implements [Vault].
func (v *vault) Find(ctx context.Context, hint jwk.Hint) (jwk.KeyPair, error) {
	if hint == nil {
		return nil, errors.New("nil hint provided")
	}

	keys, err := v.store.Load(ctx, v.kek)
	if err != nil {
		return nil, err
	}

	for _, k := range keys {
		if k.Algorithm() != hint.Algorithm() {
			continue
		}

		kid := hint.KeyID()
		if kid != "" && k.KeyID() == kid {
			return k, nil
		}
	}

	return nil, ErrKeyNotFound
}

// Next implements [Vault].
func (v *vault) Next(ctx context.Context) (jwk.KeyPair, error) {
	keys, err := v.store.Load(ctx, v.kek)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, ErrKeyNotFound
	}
	return keys[0], nil
}

var _ Vault = (*vault)(nil)
