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

package nonce_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/nonce"
)

func TestBytes(t *testing.T) {
	t.Parallel()

	b, err := nonce.Bytes(16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp, act := 16, len(b); exp != act {
		t.Fatalf("expected %d bytes, got %d", exp, act)
	}

	if _, err := nonce.Bytes(0); !errors.Is(err, nonce.ErrInvalidSize) {
		t.Fatalf("expected invalid size error, got %v", err)
	}
}

func TestOpaque(t *testing.T) {
	t.Parallel()

	tok1, err := nonce.Opaque(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp, act := 43, len(tok1); exp != act {
		t.Fatalf("expected %d chars for 32 bytes, got %d (%s)", exp, act, tok1)
	}

	tok2, err := nonce.Opaque(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok1 == tok2 {
		t.Fatalf("expected unique tokens, got identical: %s", tok1)
	}

	if _, err := nonce.Opaque(0); !errors.Is(err, nonce.ErrInvalidSize) {
		t.Fatalf("expected invalid size error, got %v", err)
	}
}

func TestHex(t *testing.T) {
	t.Parallel()

	hex1, err := nonce.Hex(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp, act := 64, len(hex1); exp != act {
		t.Fatalf("expected %d hex chars, got %d (%s)", exp, act, hex1)
	}

	if _, err := nonce.Hex(0); !errors.Is(err, nonce.ErrInvalidSize) {
		t.Fatalf("expected invalid size error, got %v", err)
	}
}

func TestString(t *testing.T) {
	t.Parallel()

	const alphabet = "ABCDEF012345"

	s, err := nonce.String(10, alphabet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp, act := 10, len(s); exp != act {
		t.Fatalf("expected length %d, got %d", exp, act)
	}

	for _, c := range s {
		if !strings.ContainsRune(alphabet, c) {
			t.Fatalf("character %q not in alphabet %q", c, alphabet)
		}
	}

	if _, err := nonce.String(0, "ab"); !errors.Is(err, nonce.ErrInvalidSize) {
		t.Fatalf("expected invalid size error, got %v", err)
	}

	if _, err := nonce.String(1, ""); !errors.Is(err, nonce.ErrEmptyAlphabet) {
		t.Fatalf("expected empty alphabet error, got %v", err)
	}
}
