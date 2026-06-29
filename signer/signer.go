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

// Signer is an interface extending crypto.Signer to support context propagation
// for external signing services (e.g., Cloud KMS).
type Signer interface {
	crypto.Signer

	// SignContext creates a signature, honoring the provided context for
	// cancellation and deadlines.
	SignContext(
		ctx context.Context,
		rand io.Reader,
		digest []byte,
		opts crypto.SignerOpts,
	) (signature []byte, err error)
}

// From adapts a standard crypto.Signer into a context-aware Signer.
// If the underlying signer already implements Signer, it is returned directly.
// Otherwise, a wrapper is returned that ignores the context and calls the
// standard Sign method.
func From(s crypto.Signer) Signer {
	if cast, ok := s.(Signer); ok {
		return cast
	}
	return &wrapper{s}
}

type wrapper struct {
	crypto.Signer
}

// SignContext implements Signer.
func (w *wrapper) SignContext(
	ctx context.Context,
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) (signature []byte, err error) {
	return w.Sign(rand, digest, opts)
}
