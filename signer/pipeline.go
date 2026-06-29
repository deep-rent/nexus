// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signer

import (
	"context"
	"io"
)

// Document holds the state throughout the document signing pipeline.
type Document struct {
	// Raw is the original document payload stream.
	Raw io.Reader
	// Digest is the pre-computed hash of the document (e.g., SHA-256).
	Digest []byte
	// Signature is the raw cryptographic signature (e.g., from an HSM).
	Signature []byte
	// Container is the final packaged output (PAdES, CMS, or PKCS#7 blob).
	Container []byte
}

// Step defines a single step in the document signing pipeline.
type Step func(ctx context.Context, doc *Document) error

// Interceptor allows decorating handlers (e.g., for TSA, audit logging,
// WORM storage).
type Interceptor func(next Step) Step

// Pipeline orchestrates the document signing flow, tying together a core HSM
// signer and a chain of middlewares.
type Pipeline struct {
	signer       Signer
	interceptors []Interceptor
}

// NewPipeline creates a new document signing pipeline.
func NewPipeline(s Signer, interceptors ...Interceptor) *Pipeline {
	return &Pipeline{
		signer:       s,
		interceptors: interceptors,
	}
}

// Execute runs the document through the signing pipeline.
//
// To be implemented: This will chain the middlewares around a base handler that
// digests the document and signs it using the core HSM signer.
func (p *Pipeline) Execute(ctx context.Context, doc io.Reader) ([]byte, error) {
	panic("not implemented")
}
