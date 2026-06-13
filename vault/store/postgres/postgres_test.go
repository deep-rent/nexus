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

package postgres_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	testpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/deep-rent/nexus/vault"
	"github.com/deep-rent/nexus/vault/store/postgres"
)

func setupDB(t *testing.T) *sql.DB {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test: database setup required")
	}

	ctx := context.Background()

	container, err := testpg.Run(ctx,
		"postgres:16-alpine",
		testpg.WithDatabase("testdb"),
		testpg.WithUsername("user"),
		testpg.WithPassword("pass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Errorf("failed to terminate container: %v", err)
		}
	})

	ds, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get connection string: %v", err)
	}

	db, err := sql.Open("pgx", ds)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("failed to close database: %v", err)
		}
	})

	return db
}

func TestStore_Integration(t *testing.T) {
	db := setupDB(t)
	ctx := context.Background()

	store := postgres.New(db)
	if err := store.Init(ctx); err != nil {
		t.Fatalf("failed to init store schema: %v", err)
	}

	kek := []byte("01234567890123456789012345678901") // 32 bytes

	t.Run("Generate and Load", func(t *testing.T) {
		k1, err := store.Generate(ctx, kek)
		if err != nil {
			t.Fatalf("unexpected error generating key: %v", err)
		}
		
		time.Sleep(100 * time.Millisecond) // ensure creation time differs

		k2, err := store.Generate(ctx, kek)
		if err != nil {
			t.Fatalf("unexpected error generating key: %v", err)
		}

		keys, err := store.Load(ctx, kek)
		if err != nil {
			t.Fatalf("unexpected error loading keys: %v", err)
		}

		if len(keys) != 2 {
			t.Fatalf("expected 2 keys, got %d", len(keys))
		}

		// Newest should be first (k2)
		if keys[0].KeyID() != k2.KeyID() {
			t.Errorf("expected newest key to be first")
		}
		if keys[1].KeyID() != k1.KeyID() {
			t.Errorf("expected older key to be second")
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		// Generate a key to revoke
		k, err := store.Generate(ctx, kek)
		if err != nil {
			t.Fatalf("unexpected error generating key: %v", err)
		}

		err = store.Revoke(ctx, k.KeyID())
		if err != nil {
			t.Fatalf("unexpected error revoking key: %v", err)
		}

		err = store.Revoke(ctx, k.KeyID())
		if !errors.Is(err, vault.ErrKeyNotFound) {
			t.Errorf("expected ErrKeyNotFound when revoking already revoked key, got %v", err)
		}

		// Loading should not include the revoked key
		keys, err := store.Load(ctx, kek)
		if err != nil {
			t.Fatalf("unexpected error loading keys: %v", err)
		}

		for _, loadedKey := range keys {
			if loadedKey.KeyID() == k.KeyID() {
				t.Errorf("revoked key was still returned by Load")
			}
		}
	})

	t.Run("Add from PEM", func(t *testing.T) {
		prv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}
		pkcs8Data, err := x509.MarshalPKCS8PrivateKey(prv)
		if err != nil {
			t.Fatalf("failed to marshal pkcs8: %v", err)
		}
		pemBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8Data,
		}
		pemData := pem.EncodeToMemory(pemBlock)

		k, err := store.Add(ctx, kek, pemData)
		if err != nil {
			t.Fatalf("unexpected error adding key: %v", err)
		}

		if k.KeyID() == "" {
			t.Errorf("expected assigned KeyID for added key")
		}

		keys, err := store.Load(ctx, kek)
		if err != nil {
			t.Fatalf("unexpected error loading keys: %v", err)
		}

		// Verify the added key is returned and is the most recent
		if len(keys) == 0 || keys[0].KeyID() != k.KeyID() {
			t.Errorf("expected added key to be the first key returned")
		}
	})

	t.Run("Load with invalid KEK", func(t *testing.T) {
		wrongKEK := []byte("11111111111111111111111111111111")
		_, err := store.Load(ctx, wrongKEK)
		if err == nil {
			t.Errorf("expected error when loading with wrong KEK")
		}
	})
}
