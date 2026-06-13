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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"iter"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/router"
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

	// Active retrieves the currently active [jwk.KeyPair] intended for signing
	// new tokens. It returns [ErrKeyNotFound] if the vault is empty.
	Active(ctx context.Context) (jwk.KeyPair, error)

	// ServeHTTP exposes the vault's public keys as a JSON Web Key Set (JWKS).
	// It implements the [router.Handler] interface.
	ServeHTTP(e *router.Exchange) error
}

// Source represents an external backend (e.g., KMS, HashiCorp Vault) capable of
// supplying signing keys.
type Source interface {
	// Load retrieves all available signing keys from the external source.
	// The implementation must return the keys such that the currently active
	// signing key is the first element in the slice.
	Load(ctx context.Context) ([]jwk.KeyPair, error)
}

// vault is the concrete implementation of [Vault]. It uses a [Source] to
// retrieve the key material on demand.
type vault struct {
	source Source

	mu        sync.RWMutex
	jwksBytes []byte
	etag      string
	lastMod   time.Time
}

// New creates a new [Vault] backed by the provided [Source].
func New(source Source) Vault {
	return &vault{
		source: source,
	}
}

// Keys implements [Vault].
func (v *vault) Keys(ctx context.Context) (iter.Seq[jwk.KeyPair], error) {
	keys, err := v.source.Load(ctx)
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

	keys, err := v.source.Load(ctx)
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

		x5t := hint.Thumbprint()
		if x5t != "" && k.Thumbprint() == x5t {
			return k, nil
		}
	}

	return nil, ErrKeyNotFound
}

// Active implements [Vault].
func (v *vault) Active(ctx context.Context) (jwk.KeyPair, error) {
	keys, err := v.source.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, ErrKeyNotFound
	}
	return keys[0], nil
}

// ServeHTTP implements [router.Handler] and [Vault].
func (v *vault) ServeHTTP(e *router.Exchange) error {
	ctx := e.Context()
	keys, err := v.source.Load(ctx)
	if err != nil {
		return err
	}

	// Stabilize the output since source.Load() might return keys in a
	// rotated order. We sort them by KeyID or Thumbprint.
	sortedKeys := make([]jwk.KeyPair, len(keys))
	copy(sortedKeys, keys)
	slices.SortFunc(sortedKeys, func(a, b jwk.KeyPair) int {
		idA := a.KeyID()
		if idA == "" {
			idA = a.Thumbprint()
		}
		idB := b.KeyID()
		if idB == "" {
			idB = b.Thumbprint()
		}
		if idA < idB {
			return -1
		}
		if idA > idB {
			return 1
		}
		return 0
	})

	// Convert to jwk.Key slice for Set creation
	pubKeys := make([]jwk.Key, len(sortedKeys))
	for i, k := range sortedKeys {
		pubKeys[i] = k
	}

	set := jwk.NewSet(pubKeys...)
	payload, err := jwk.WriteSet(set)
	if err != nil {
		return err
	}

	hash := sha256.Sum256(payload)
	etag := `W/"` + hex.EncodeToString(hash[:]) + `"`

	v.mu.Lock()
	if v.etag != etag {
		v.etag = etag
		v.jwksBytes = payload
		v.lastMod = time.Now().UTC()
	}
	lastMod := v.lastMod
	v.mu.Unlock()

	// Check conditional headers
	if v := e.GetHeader("If-None-Match"); v != "" {
		if v == etag {
			e.Status(http.StatusNotModified)
			return nil
		}
	} else if v := e.GetHeader("If-Modified-Since"); v != "" {
		if t, err := time.Parse(http.TimeFormat, v); err == nil {
			if !lastMod.After(t.Add(time.Second)) { // Ignore sub-second precision
				e.Status(http.StatusNotModified)
				return nil
			}
		}
	}

	e.SetHeader("Content-Type", "application/jwk-set+json")
	e.SetHeader("ETag", etag)
	e.SetHeader("Last-Modified", lastMod.Format(http.TimeFormat))
	e.Status(http.StatusOK)

	_, err = e.W.Write(payload)
	return err
}

var _ Vault = (*vault)(nil)
