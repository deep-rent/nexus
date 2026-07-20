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

// Package sign provides context-aware cryptographic signing interfaces.
//
// Package sign bridges the gap between Go's standard [crypto.Signer] and
// context-aware operations. It provides a [Signer] interface that respects
// context cancellation and deadlines during cryptographic operations.
//
// # Usage
//
// The package offers utilities for adapting standard signers and parsing keys:
//
//   - [From]: Wraps a standard [crypto.Signer] into a context-aware [Signer].
//   - [To]: Unwraps or adapts a [Signer] back to a standard [crypto.Signer]
//     with a baked-in context.
//   - [Decode]: Parses PEM-encoded private keys (PKCS8, EC, PKCS1) into a
//     ready-to-use [Signer].
//   - [Encode]: Serializes private keys back into PKCS8 PEM format.
//
// PKCS8 covers all standard library key types, including post-quantum
// ML-DSA seed keys ([*crypto/mldsa.PrivateKey]) as of Go 1.27.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//
//	signer, err := sign.Decode(pemData)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	sig, err := signer.Sign(ctx, rand.Reader, digest, nil)
package sign

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
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

// Decode decodes a PEM block and parses the contained private key into a
// [Signer]. It supports standard PKCS8 (including ML-DSA seed keys), EC, and
// PKCS1 private keys.
func Decode(data []byte) (Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	bytes := block.Bytes
	// Try standard PKCS8 first
	var (
		key any
		err error
	)
	key, err = x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		err1 := err
		// Fallback for EC private keys
		if key, err = x509.ParseECPrivateKey(bytes); err != nil {
			err2 := err
			// Fallback for RSA PKCS1
			if key, err = x509.ParsePKCS1PrivateKey(bytes); err != nil {
				return nil, fmt.Errorf(
					"failed to parse private key: %w",
					errors.Join(err1, err2, err),
				)
			}
		}
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a signer")
	}

	return From(signer), nil
}

// Encode encodes a cryptographic private key into a standard PKCS8 PEM
// formatted byte sequence. It accepts standard library private keys (e.g.,
// [*rsa.PrivateKey], [*ecdsa.PrivateKey], [ed25519.PrivateKey],
// [*crypto/mldsa.PrivateKey]) or context-aware [Signer] wrappers returned
// by this package.
func Encode(key any) ([]byte, error) {
	if w, ok := key.(*ctxWrapper); ok {
		key = w.signer
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(block), nil
}

// DecodePublic decodes a PEM block and parses the contained public key into a
// standard [crypto.PublicKey]. It supports standard PKIX public keys.
func DecodePublic(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return key, nil
}

// EncodePublic encodes a cryptographic public key into a standard PKIX PEM
// formatted byte sequence. It accepts standard library public keys.
func EncodePublic(key crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(block), nil
}
