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

	"crypto/mldsa"

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
		t.Errorf("public key: got %s; want %s", act, exp)
	}

	sig, err := s.Sign(t.Context(), nil, nil, nil)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if exp, act := "bar", string(sig); exp != act {
		t.Errorf("signature: got %s; want %s", act, exp)
	}
}

func TestFrom_CancelledContext(t *testing.T) {
	t.Parallel()

	s := sign.From(&mockStdSigner{})

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // cancel context early

	_, err := s.Sign(ctx, nil, nil, nil)
	if err == nil {
		t.Fatal("should have returned an error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("got %v; want context.Canceled", err)
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
		t.Errorf("public key: got %s; want %s", act, exp)
	}

	sig, err := s.Sign(nil, nil, nil)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if exp, act := "ctx-bar", string(sig); exp != act {
		t.Errorf("signature: got %s; want %s", act, exp)
	}
	if m.passedCtx != ctx {
		t.Error("should have propagated the context to the underlying signer")
	}
}

func TestTo_Unwraps(t *testing.T) {
	t.Parallel()

	orig := &mockStdSigner{}
	wrapped := sign.From(orig)
	unwrapped := sign.To(t.Context(), wrapped)

	if orig != unwrapped {
		t.Error("should have unwrapped to the original signer")
	}
}

func TestDecode(t *testing.T) {
	t.Parallel()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key generation: should not have returned an error: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshalling: should not have returned an error: %v", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	data := pem.EncodeToMemory(block)

	s, err := sign.Decode(data)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if s == nil {
		t.Fatal("got nil signer; want non-nil")
	}

	pub, ok := s.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key: got %T; want *ecdsa.PublicKey", s.Public())
	}
	if !pub.Equal(&k.PublicKey) {
		t.Error("public key does not match the generated key")
	}

	msg := []byte("payload")
	digest := crypto.SHA256.New()
	digest.Write(msg)
	hashed := digest.Sum(nil)

	sig, err := s.Sign(t.Context(), rand.Reader, hashed, nil)
	if err != nil {
		t.Fatalf("signing: should not have returned an error: %v", err)
	}
	if !ecdsa.VerifyASN1(&k.PublicKey, hashed, sig) {
		t.Error("signature should have verified")
	}
}

func TestDecode_Error(t *testing.T) {
	t.Parallel()

	t.Run("invalid block", func(t *testing.T) {
		t.Parallel()
		if _, err := sign.Decode([]byte("invalid")); err == nil {
			t.Error("should have returned an error")
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
			t.Fatal("should have returned an error")
		}
		if err.Error() == "failed to parse private key" {
			t.Errorf("got unwrapped error %v; want a wrapped error", err)
		}
	})
}

func TestEncode(t *testing.T) {
	t.Parallel()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key generation: should not have returned an error: %v", err)
	}

	pem1, err := sign.Encode(k)
	if err != nil {
		t.Fatalf("raw key: should not have returned an error: %v", err)
	}
	if len(pem1) == 0 {
		t.Error("got empty PEM; want non-empty")
	}

	wrapped := sign.From(k)
	pem2, err := sign.Encode(wrapped)
	if err != nil {
		t.Fatalf("wrapped key: should not have returned an error: %v", err)
	}
	if string(pem1) != string(pem2) {
		t.Error("raw and wrapped key should have encoded identically")
	}

	parsed, err := sign.Decode(pem1)
	if err != nil {
		t.Fatalf("decoding: should not have returned an error: %v", err)
	}
	if parsed == nil {
		t.Fatal("got nil signer; want non-nil")
	}
}

func TestEncodeDecode_MLDSA(t *testing.T) {
	t.Parallel()

	k, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("key generation: should not have returned an error: %v", err)
	}

	data, err := sign.Encode(k)
	if err != nil {
		t.Fatalf("encoding: should not have returned an error: %v", err)
	}

	s, err := sign.Decode(data)
	if err != nil {
		t.Fatalf("decoding: should not have returned an error: %v", err)
	}

	pub, ok := s.Public().(*mldsa.PublicKey)
	if !ok {
		t.Fatalf("public key: got %T; want *mldsa.PublicKey", s.Public())
	}
	if !pub.Equal(k.PublicKey()) {
		t.Error("public key does not match the generated key")
	}

	msg := []byte("payload")
	sig, err := s.Sign(t.Context(), rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("signing: should not have returned an error: %v", err)
	}
	if err := mldsa.Verify(pub, msg, sig, nil); err != nil {
		t.Errorf("signature should have verified: %v", err)
	}
}

func TestEncode_Error(t *testing.T) {
	t.Parallel()

	_, err := sign.Encode("not-a-key")
	if err == nil {
		t.Error("should have returned an error")
	}
}
