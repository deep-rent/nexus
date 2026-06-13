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

// Package postgres provides a PostgreSQL implementation of vault.Store.
package postgres

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"io"
	"time"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/uuid"
	"github.com/deep-rent/nexus/vault"
)

// Store implements vault.Store using PostgreSQL.
type Store struct {
	db *sql.DB
}

// New creates a new PostgreSQL store.
func New(db *sql.DB) *Store {
	return &Store{
		db: db,
	}
}

// Init creates the necessary database tables if they do not exist.
func (s *Store) Init(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS vault_keys (
			kid TEXT PRIMARY KEY,
			alg TEXT NOT NULL,
			encrypted_material BYTEA NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			revoked_at TIMESTAMP WITH TIME ZONE
		)
	`)
	return err
}

func encrypt(plaintext, kek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	// Prepend nonce to ciphertext
	return append(nonce, ciphertext...), nil
}

func decrypt(ciphertext, kek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

func (s *Store) Load(ctx context.Context, kek []byte) ([]jwk.KeyPair, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT kid, alg, encrypted_material 
		FROM vault_keys 
		WHERE revoked_at IS NULL 
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []jwk.KeyPair
	for rows.Next() {
		var kid, alg string
		var enc []byte
		if err := rows.Scan(&kid, &alg, &enc); err != nil {
			return nil, err
		}

		dec, err := decrypt(enc, kek)
		if err != nil {
			return nil, err
		}

		rawKey, err := x509.ParsePKCS8PrivateKey(dec)
		if err != nil {
			return nil, err
		}

		signer, ok := rawKey.(crypto.Signer)
		if !ok {
			return nil, errors.New("key does not implement crypto.Signer")
		}

		var pair jwk.KeyPair
		switch alg {
		case "RS256":
			pair = jwk.NewKeyBuilder(jwa.RS256).WithKeyID(kid).BuildPair(signer)
		case "RS384":
			pair = jwk.NewKeyBuilder(jwa.RS384).WithKeyID(kid).BuildPair(signer)
		case "RS512":
			pair = jwk.NewKeyBuilder(jwa.RS512).WithKeyID(kid).BuildPair(signer)
		case "PS256":
			pair = jwk.NewKeyBuilder(jwa.PS256).WithKeyID(kid).BuildPair(signer)
		case "PS384":
			pair = jwk.NewKeyBuilder(jwa.PS384).WithKeyID(kid).BuildPair(signer)
		case "PS512":
			pair = jwk.NewKeyBuilder(jwa.PS512).WithKeyID(kid).BuildPair(signer)
		case "ES256":
			pair = jwk.NewKeyBuilder(jwa.ES256).WithKeyID(kid).BuildPair(signer)
		case "ES384":
			pair = jwk.NewKeyBuilder(jwa.ES384).WithKeyID(kid).BuildPair(signer)
		case "ES512":
			pair = jwk.NewKeyBuilder(jwa.ES512).WithKeyID(kid).BuildPair(signer)
		case "EdDSA":
			pair = jwk.NewKeyBuilder(jwa.EdDSA).WithKeyID(kid).BuildPair(signer)
		default:
			return nil, errors.New("unsupported algorithm: " + alg)
		}
		keys = append(keys, pair)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return keys, nil
}

func (s *Store) Revoke(ctx context.Context, kid string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE vault_keys 
		SET revoked_at = NOW() 
		WHERE kid = $1 AND revoked_at IS NULL
	`, kid)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return vault.ErrKeyNotFound
	}
	return nil
}

func (s *Store) Generate(ctx context.Context, kek []byte) (jwk.KeyPair, error) {
	// Default to RS256 for compatibility with existing codebase defaults
	prv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	alg := jwa.RS256
	kid := uuid.New().String()

	pkcs8Data, err := x509.MarshalPKCS8PrivateKey(prv)
	if err != nil {
		return nil, err
	}

	enc, err := encrypt(pkcs8Data, kek)
	if err != nil {
		return nil, err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO vault_keys (kid, alg, encrypted_material, created_at)
		VALUES ($1, $2, $3, $4)
	`, kid, alg.String(), enc, time.Now().UTC())
	if err != nil {
		return nil, err
	}

	return jwk.NewKeyBuilder(alg).WithKeyID(kid).BuildPair(prv), nil
}

func (s *Store) Add(ctx context.Context, kek []byte, pemData []byte) (jwk.KeyPair, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing private key")
	}

	var rawKey any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		rawKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		rawKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		rawKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, errors.New("unsupported PEM block type")
	}
	if err != nil {
		return nil, err
	}

	alg := jwa.RS256 // fallback
	switch rawKey.(type) {
	case *rsa.PrivateKey:
		alg = jwa.RS256
	}

	signer, ok := rawKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("key does not implement crypto.Signer")
	}

	pkcs8Data, err := x509.MarshalPKCS8PrivateKey(rawKey)
	if err != nil {
		return nil, err
	}

	enc, err := encrypt(pkcs8Data, kek)
	if err != nil {
		return nil, err
	}

	kid := uuid.New().String()

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO vault_keys (kid, alg, encrypted_material, created_at)
		VALUES ($1, $2, $3, $4)
	`, kid, alg.String(), enc, time.Now().UTC())
	if err != nil {
		return nil, err
	}

	return jwk.NewKeyBuilder(alg).WithKeyID(kid).BuildPair(signer), nil
}

var _ vault.Store = (*Store)(nil)
