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

// Package mock provides an in-memory implementation of vault.Store for testing.
package mock

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"time"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/uuid"
	"github.com/deep-rent/nexus/vault"
)

type record struct {
	key       jwk.KeyPair
	createdAt time.Time
	revokedAt time.Time
}

// Store is an in-memory implementation of vault.Store.
// It does not actually perform encryption but validates that the correct KEK is used
// to simulate the behavior of a secure backend.
type Store struct {
	mu      sync.RWMutex
	records []record
	kek     []byte
}

// New creates a new in-memory Store with the given simulated KEK.
// It will only decrypt (return keys) if the provided KEK matches this one.
func New(kek []byte) *Store {
	return &Store{
		kek:     append([]byte(nil), kek...),
	}
}

func (s *Store) validateKEK(kek []byte) error {
	if len(kek) != len(s.kek) {
		return errors.New("invalid key encryption key")
	}
	for i := range kek {
		if kek[i] != s.kek[i] {
			return errors.New("invalid key encryption key")
		}
	}
	return nil
}

// Load retrieves all non-revoked keys. The most recently created key is returned first.
func (s *Store) Load(ctx context.Context, kek []byte) ([]jwk.KeyPair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.validateKEK(kek); err != nil {
		return nil, err
	}

	var keys []jwk.KeyPair
	// Return in reverse chronological order so the newest is first (active key)
	for i := len(s.records) - 1; i >= 0; i-- {
		if s.records[i].revokedAt.IsZero() {
			keys = append(keys, s.records[i].key)
		}
	}
	return keys, nil
}

// Revoke invalidates a key by its Key ID.
func (s *Store) Revoke(ctx context.Context, kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.records {
		if s.records[i].key.KeyID() == kid {
			if !s.records[i].revokedAt.IsZero() {
				return errors.New("key already revoked")
			}
			s.records[i].revokedAt = time.Now().UTC()
			return nil
		}
	}
	return errors.New("key not found")
}

// Generate creates a new key pair and stores it.
func (s *Store) Generate(ctx context.Context, kek []byte) (jwk.KeyPair, error) {
	if err := s.validateKEK(kek); err != nil {
		return nil, err
	}

	// Defaulting to EdDSA for generation if not specified, 
	// but using RS256 here for compatibility with existing tests unless they change.
	// We'll use RS256 to ensure tests using RSA keys work out of the box.
	prv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	kid := uuid.New().String()
	key := jwk.NewKeyBuilder(jwa.RS256).WithKeyID(kid).BuildPair(prv)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.records = append(s.records, record{
		key:       key,
		createdAt: time.Now().UTC(),
	})

	return key, nil
}

// Add imports an existing key pair.
func (s *Store) Add(ctx context.Context, kek []byte, pemData []byte) (jwk.KeyPair, error) {
	if err := s.validateKEK(kek); err != nil {
		return nil, err
	}

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

	kid := uuid.New().String()
	pair := jwk.NewKeyBuilder(alg).WithKeyID(kid).BuildPair(signer)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.records = append(s.records, record{
		key:       pair,
		createdAt: time.Now().UTC(),
	})

	return pair, nil
}

// Prepopulate adds existing keys without KEK validation for test setup.
func (s *Store) Prepopulate(keys ...jwk.KeyPair) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range keys {
		s.records = append(s.records, record{
			key:       k,
			createdAt: time.Now().UTC(),
		})
	}
}

var _ vault.Store = (*Store)(nil)
