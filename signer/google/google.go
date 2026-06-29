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

// Package google provides a Google Cloud KMS implementation of the signer interface.
package google

import (
	"context"
	"crypto"
	"io"

	"github.com/deep-rent/nexus/signer"
)

// Signer is a context-aware cryptographic signer backed by Google Cloud KMS.
type Signer struct {
	// To be implemented:
	// client *kms.KeyManagementClient
	// keyName string
	// pubKey crypto.PublicKey
}

// Public returns the public key associated with the KMS key.
func (s *Signer) Public() crypto.PublicKey {
	panic("not implemented")
}

// Sign performs the cryptographic signing operation using Cloud KMS.
func (s *Signer) Sign(ctx context.Context, rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	panic("not implemented")
}

var _ signer.Signer = (*Signer)(nil)
