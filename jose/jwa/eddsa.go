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
	"crypto/ed25519"
	"crypto/rand"

	sign "github.com/deep-rent/nexus/sign"
)

// ed implements the EdDSA family of algorithms.
type ed struct{}

// Verify checks an EdDSA signature, supporting Ed25519.
func (a *ed) Verify(key ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(key, msg, sig)
}

// Sign creates an EdDSA signature using the provided signer.
func (a *ed) Sign(
	ctx context.Context,
	s sign.Signer,
	msg []byte,
) ([]byte, error) {
	return s.Sign(ctx, rand.Reader, msg, crypto.Hash(0))
}

// Generate creates a new Ed25519 key pair.
func (a *ed) Generate() (crypto.Signer, error) {
	_, prv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return prv, nil
}

// String returns the JWA algorithm name.
func (a *ed) String() string {
	return "EdDSA"
}

// EdDSA represents the EdDSA signature algorithm. It supports the Ed25519
// curve.
var EdDSA Algorithm[ed25519.PublicKey] = &ed{}
