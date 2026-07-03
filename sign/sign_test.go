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

package sign_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"testing"

	"github.com/deep-rent/nexus/sign"
)

type mockStdSigner struct{}

func (d *mockStdSigner) Public() crypto.PublicKey { return "foo" }
func (d *mockStdSigner) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) (signature []byte, err error) {
	return []byte("bar"), nil
}

var _ crypto.Signer = (*mockStdSigner)(nil)

func TestFrom(t *testing.T) {
	t.Parallel()

	s := sign.From(&mockStdSigner{})

	key := s.Public()
	if exp, act := "foo", key.(string); exp != act {
		t.Errorf("expected %s, got %s", exp, act)
	}

	sig, err := s.Sign(t.Context(), nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp, act := "bar", string(sig); exp != act {
		t.Errorf("expected %s, got %s", exp, act)
	}
}

func TestFrom_CancelledContext(t *testing.T) {
	t.Parallel()

	s := sign.From(&mockStdSigner{})

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // cancel context early

	_, err := s.Sign(ctx, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

type mockCtxSigner struct {
	passedCtx context.Context
}

func (m *mockCtxSigner) Public() crypto.PublicKey { return "ctx-foo" }

func (m *mockCtxSigner) Sign(
	ctx context.Context,
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) ([]byte, error) {
	m.passedCtx = ctx
	return []byte("ctx-bar"), nil
}

var _ sign.Signer = (*mockCtxSigner)(nil)

func TestTo(t *testing.T) {
	t.Parallel()

	m := &mockCtxSigner{}
	ctx := t.Context()

	s := sign.To(ctx, m)

	key := s.Public()
	if exp, act := "ctx-foo", key.(string); exp != act {
		t.Errorf("expected %s, got %s", exp, act)
	}

	sig, err := s.Sign(nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp, act := "ctx-bar", string(sig); exp != act {
		t.Errorf("expected %s, got %s", exp, act)
	}
	if m.passedCtx != ctx {
		t.Error("context was not propagated to underlying Signer")
	}
}

func TestTo_Unwraps(t *testing.T) {
	t.Parallel()

	orig := &mockStdSigner{}
	wrapped := sign.From(orig)
	unwrapped := sign.To(t.Context(), wrapped)

	if orig != unwrapped {
		t.Error("expected To() to unwrap From() wrapper to original signer")
	}
}

func TestDecode(t *testing.T) {
	t.Parallel()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	data := pem.EncodeToMemory(block)

	s, err := sign.Decode(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if s == nil {
		t.Fatal("expected Signer, got nil")
	}

	pub, ok := s.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", s.Public())
	}
	if pub.X.Cmp(k.X) != 0 || pub.Y.Cmp(k.Y) != 0 {
		t.Error("public key mismatch")
	}
}

func TestDecode_Error(t *testing.T) {
	t.Parallel()

	t.Run("invalid block", func(t *testing.T) {
		t.Parallel()
		if _, err := sign.Decode([]byte("invalid")); err == nil {
			t.Error("expected error for invalid block, got nil")
		}
	})

	t.Run("invalid key material", func(t *testing.T) {
		t.Parallel()
		block := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("invalid-key-data"),
		}
		pemData := pem.EncodeToMemory(block)
		_, err := sign.Decode(pemData)
		if err == nil {
			t.Fatal("expected error for invalid key material, got nil")
		}
		if err.Error() == "failed to parse private key" {
			t.Errorf("expected wrapped error, got: %v", err)
		}
	})
}

func TestEncode(t *testing.T) {
	t.Parallel()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Test raw key
	pem1, err := sign.Encode(k)
	if err != nil {
		t.Fatalf("unexpected error serializing raw key: %v", err)
	}
	if len(pem1) == 0 {
		t.Error("expected non-empty PEM string")
	}

	// Test wrapped key
	wrapped := sign.From(k)
	pem2, err := sign.Encode(wrapped)
	if err != nil {
		t.Fatalf("unexpected error serializing wrapped key: %v", err)
	}
	if string(pem1) != string(pem2) {
		t.Error("expected serialized output to match for raw and wrapped key")
	}

	// Verify it can be parsed back
	parsed, err := sign.Decode(pem1)
	if err != nil {
		t.Fatalf("failed to parse generated PEM: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestEncode_Error(t *testing.T) {
	t.Parallel()

	_, err := sign.Encode("not-a-key")
	if err == nil {
		t.Error("expected error for invalid key type, got nil")
	}
}
