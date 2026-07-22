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

package jwa

import (
	"context"
	"crypto"
	"hash"
	"sync"

	sign "github.com/deep-rent/nexus/sec/sign"
)

// Algorithm represents a JWA digital signature algorithm.
//
// The type parameter PublicKey restricts the key type acceptable for
// verification, enforcing algorithm-to-key-type constraints at compile time
// where possible.
type Algorithm[PublicKey any] interface {
	// Verify checks whether sig is a valid signature for msg under the given
	// public key. It MUST NOT return true if the public key type or parameters
	// do not match the algorithm.
	Verify(key PublicKey, msg, sig []byte) bool

	// Sign creates a digital signature for msg using the provided opaque
	// signer. The signer's public key MUST match the algorithm's requirements.
	Sign(ctx context.Context, s sign.Signer, msg []byte) ([]byte, error)

	// Generate creates a new private key suitable for this algorithm using
	// [crypto/rand.Reader] as the entropy source.
	Generate() (crypto.Signer, error)

	// String returns the JWA algorithm identifier (e.g., "RS256").
	String() string
}

// hashPool manages a pool of [hash.Hash] objects to reduce allocations.
type hashPool struct {
	// Hash is the underlying hash identifier.
	Hash crypto.Hash
	// pool is the [sync.Pool] containing initialized [hash.Hash] instances.
	pool *sync.Pool
}

// newHashPool creates a new [hashPool] for the given hash function.
func newHashPool(hash crypto.Hash) *hashPool {
	pool := &sync.Pool{
		New: func() any {
			return hash.New()
		},
	}
	return &hashPool{
		Hash: hash,
		pool: pool,
	}
}

// Get retrieves a [hash.Hash] from the pool.
func (p *hashPool) Get() hash.Hash {
	h := p.pool.Get()
	return h.(hash.Hash)
}

// Put returns a [hash.Hash] to the pool after resetting it.
func (p *hashPool) Put(h hash.Hash) {
	h.Reset()
	p.pool.Put(h)
}
