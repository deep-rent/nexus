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

package signer_test

import (
	"context"
	"crypto"
	"io"
	"testing"

	"github.com/deep-rent/nexus/signer"
)

type mockNativeSigner struct{}

func (d *mockNativeSigner) Public() crypto.PublicKey { return nil }
func (d *mockNativeSigner) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) (signature []byte, err error) {
	return []byte("crypto"), nil
}

type mockSigner struct{}

func (d *mockSigner) Public() crypto.PublicKey { return nil }
func (d *mockSigner) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) (signature []byte, err error) {
	return []byte("crypto"), nil
}

func (d *mockSigner) SignContext(
	ctx context.Context,
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) (signature []byte, err error) {
	return []byte("context"), nil
}

func TestFrom_NativeSigner(t *testing.T) {
	t.Parallel()

	s := signer.From(&mockNativeSigner{})
	sig, err := s.SignContext(t.Context(), nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp, act := "crypto", string(sig); exp != act {
		t.Errorf("From() expected %s, got %s", exp, act)
	}
}

func TestFrom_Signer(t *testing.T) {
	t.Parallel()

	s := signer.From(&mockSigner{})
	sig, err := s.SignContext(t.Context(), nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp, act := "context", string(sig); exp != act {
		t.Errorf("From() expected %s, got %s", exp, act)
	}
}
