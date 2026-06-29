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

// Package signer provides context-aware cryptographic signing interfaces.
package signer

import (
	"context"
	"crypto"
	"io"
)

// Signer is an interface similar to [crypto.Signer] but with context
// propagation.
type Signer interface {
	// Public returns the public key corresponding to the opaque, private key.
	Public() crypto.PublicKey

	// Sign creates a signature, honoring the provided context for cancellation
	// and deadlines.
	Sign(
		ctx context.Context,
		rand io.Reader,
		digest []byte,
		opts crypto.SignerOpts,
	) (signature []byte, err error)
}

// From adapts a standard [crypto.Signer] into a context-aware [Signer].
func From(s crypto.Signer) Signer {
	return &wrapper{signer: s}
}

type wrapper struct {
	signer crypto.Signer
}

// Public implements [Signer].
func (w *wrapper) Public() crypto.PublicKey { return w.signer.Public() }

// Sign implements [Signer].
func (w *wrapper) Sign(
	ctx context.Context,
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) (signature []byte, err error) {
	return w.signer.Sign(rand, digest, opts)
}

var _ Signer = (*wrapper)(nil)
