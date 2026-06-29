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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/rotor"
	"github.com/deep-rent/nexus/sign"
	"github.com/deep-rent/nexus/vault"
)

var table = crc32.MakeTable(crc32.Castagnoli)

// signer is a context-aware cryptographic signer backed by Google Cloud KMS.
type signer struct {
	client *kms.KeyManagementClient
	name   string
	key    crypto.PublicKey
}

// Public returns the public key associated with the KMS key.
func (s *signer) Public() crypto.PublicKey {
	return s.key
}

// Sign performs the cryptographic signing operation using Cloud KMS.
func (s *signer) Sign(
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

var _ sign.Signer = (*signer)(nil)

type Factory struct {
	client *kms.KeyManagementClient
	logger *slog.Logger
}

func (f *Factory) New(ctx context.Context, parent string, strategy rotor.Strategy) (vault.Vault, error) {
	req := &kmspb.ListCryptoKeyVersionsRequest{
		Parent: parent,
		Filter: "state=ENABLED",
	}

	var pairs []jwk.KeyPair
	it := f.client.ListCryptoKeyVersions(ctx, req)
	for {
		version, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate key versions: %w", err)
		}

		name := version.Name

		s, err := f.new(ctx, name)
		if err != nil {
			f.logger.WarnContext(
				ctx,
				"failed to get public key for version",
				slog.String("name", name),
				slog.Any("error", err),
			)
			continue
		}

		key := s.Public()
		kid, err := jwk.Thumbprint(key)
		if err != nil {
			f.logger.WarnContext(
				ctx,
				"failed to compute key thumbprint",
				slog.String("name", name),
				slog.Any("error", err),
			)
			continue
		}

		var p jwk.KeyPair
		switch pub := key.(type) {
		case *rsa.PublicKey:
			switch version.Algorithm {
			case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
				kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
				kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
				p = jwk.NewKeyBuilder(jwa.RS256).
					WithKeyID(kid).
					BuildPair(s)
			case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
				kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
				kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256:
				p = jwk.NewKeyBuilder(jwa.PS256).
					WithKeyID(kid).
					BuildPair(s)
			default:
				f.logger.WarnContext(ctx, "unsupported RSA algorithm")
				continue
			}
		case *ecdsa.PublicKey:
			switch version.Algorithm {
			case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
				p = jwk.NewKeyBuilder(jwa.ES256).
					WithKeyID(kid).
					BuildPair(s)
			case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
				p = jwk.NewKeyBuilder(jwa.ES384).
					WithKeyID(kid).
					BuildPair(s)
			default:
				f.logger.WarnContext(ctx, "unsupported ECDSA algorithm")
				continue
			}
		case ed25519.PublicKey:
			switch version.Algorithm {
			case kmspb.CryptoKeyVersion_EC_SIGN_ED25519:
				p = jwk.NewKeyBuilder(jwa.EdDSA).
					WithKeyID(kid).
					BuildPair(s)
			default:
				f.logger.WarnContext(ctx, "unsupported Ed25519 algorithm")
				continue
			}
		default:
			f.logger.WarnContext(ctx, "unsupported key type")
			continue
		}

		pairs = append(pairs, p)
	}

	return vault.New(pairs, strategy), nil
}

func (f *Factory) new(ctx context.Context, name string) (sign.Signer, error) {
	req := &kmspb.GetPublicKeyRequest{
		Name: name,
	}
	res, err := f.client.GetPublicKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from KMS: %w", err)
	}

	msg, _ := pem.Decode([]byte(res.Pem))
	if msg == nil {
		return nil, fmt.Errorf("failed to decode PEM block from KMS public key")
	}
	if msg.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM block type: %s", msg.Type)
	}
	key, err := x509.ParsePKIXPublicKey(msg.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &signer{
		client: f.client,
		name:   name,
		key:    key,
	}, nil
}
