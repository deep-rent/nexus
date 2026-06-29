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

// Package google provides a Google Cloud KMS implementation of the signer
// interface.
package google

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/deep-rent/nexus/signer"
)

var table = crc32.MakeTable(crc32.Castagnoli)

// Signer is a context-aware cryptographic signer backed by Google Cloud KMS.
type Signer struct {
	client *kms.KeyManagementClient
	name   string
	key    crypto.PublicKey
}

type Resource struct {
	Project    string
	Location   string
	KeyRing    string
	Key        string
	KeyVersion string
}

// New creates a new Signer instance for the specified Google Cloud KMS key
// version.
func New(
	ctx context.Context,
	client *kms.KeyManagementClient,
	resource Resource,
) (*Signer, error) {
	name := fmt.Sprintf(
		"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
		resource.Project,
		resource.Location,
		resource.KeyRing,
		resource.Key,
		resource.KeyVersion,
	)

	req := &kmspb.GetPublicKeyRequest{
		Name: name,
	}
	res, err := client.GetPublicKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from KMS: %w", err)
	}

	block, _ := pem.Decode([]byte(res.Pem))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from KMS public key")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &Signer{
		client: client,
		name:   name,
		key:    key,
	}, nil
}

// Public returns the public key associated with the KMS key.
func (s *Signer) Public() crypto.PublicKey {
	return s.key
}

// Sign performs the cryptographic signing operation using Cloud KMS.
func (s *Signer) Sign(
	ctx context.Context,
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) (signature []byte, err error) {
	checksum := crc32.Checksum(digest, table)

	hash := crypto.Hash(0)
	if opts != nil {
		hash = opts.HashFunc()
	}

	var d kmspb.Digest
	switch hash {
	case crypto.SHA256:
		d.Digest = &kmspb.Digest_Sha256{Sha256: digest}
	case crypto.SHA384:
		d.Digest = &kmspb.Digest_Sha384{Sha384: digest}
	case crypto.SHA512:
		d.Digest = &kmspb.Digest_Sha512{Sha512: digest}
	default:
		switch len(digest) {
		case 32:
			d.Digest = &kmspb.Digest_Sha256{Sha256: digest}
		case 48:
			d.Digest = &kmspb.Digest_Sha384{Sha384: digest}
		case 64:
			d.Digest = &kmspb.Digest_Sha512{Sha512: digest}
		default:
			return nil, fmt.Errorf(
				"unsupported digest type and length: %d", len(digest),
			)
		}
	}

	req := &kmspb.AsymmetricSignRequest{
		Name:         s.name,
		Digest:       &d,
		DigestCrc32C: wrapperspb.Int64(int64(checksum)),
	}

	res, err := s.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to sign digest with KMS: %w", err)
	}

	if !res.VerifiedDigestCrc32C {
		return nil, errors.New("KMS did not verify the digest CRC32C")
	}

	if int64(crc32.Checksum(res.Signature, table)) !=
		res.SignatureCrc32C.GetValue() {
		return nil, errors.New("KMS signature corrupted in transit")
	}

	if res.Name != s.name {
		return nil, fmt.Errorf("KMS used unexpected key version %q", res.Name)
	}

	return res.Signature, nil
}

var _ signer.Signer = (*Signer)(nil)
