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
package sign

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
	return &ctxWrapper{signer: s}
}

type ctxWrapper struct {
	signer crypto.Signer
}

// Public implements [Signer].
func (w *ctxWrapper) Public() crypto.PublicKey { return w.signer.Public() }

// Sign implements [Signer].
func (w *ctxWrapper) Sign(
	ctx context.Context,
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) (signature []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return w.signer.Sign(rand, digest, opts)
}

var _ Signer = (*ctxWrapper)(nil)

// To adapts a context-aware [Signer] into a standard [crypto.Signer].
//
// The provided context is baked into the resulting signer and will be used
// for all subsequent signature operations. This is useful when you need to pass
// a context-aware signer to a standard library function that only accepts a
// standard [crypto.Signer].
//
// If the provided [Signer] was originally created by [From], this function
// returns the original underlying [crypto.Signer] to prevent double-wrapping.
func To(ctx context.Context, s Signer) crypto.Signer {
	if w, ok := s.(*ctxWrapper); ok {
		return w.signer
	}
	return &stdWrapper{ctx: ctx, signer: s}
}

type stdWrapper struct {
	ctx    context.Context
	signer Signer
}

// Public implements [crypto.Signer].
func (w *stdWrapper) Public() crypto.PublicKey { return w.signer.Public() }

// Sign implements [crypto.Signer].
func (w *stdWrapper) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) ([]byte, error) {
	return w.signer.Sign(w.ctx, rand, digest, opts)
}

var _ crypto.Signer = (*stdWrapper)(nil)
