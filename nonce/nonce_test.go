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
	if len(b) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(b))
	}

	bZero, err := nonce.Bytes(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bZero != nil {
		t.Fatalf("expected nil for 0 bytes, got %v", bZero)
	}
}

func TestOpaque(t *testing.T) {
	t.Parallel()

	tok1, err := nonce.Opaque(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tok1) != 43 {
		t.Fatalf("expected 43 chars for 32 bytes, got %d (%s)", len(tok1), tok1)
	}

	tok2, err := nonce.Opaque(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok1 == tok2 {
		t.Fatalf("expected unique tokens, got identical: %s", tok1)
	}

	tokCustom, err := nonce.Opaque(16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokCustom) != 22 {
		t.Fatalf("expected 22 chars for 16 bytes base64url, got %d (%s)", len(tokCustom), tokCustom)
	}
}

func TestHex(t *testing.T) {
	t.Parallel()

	hex1, err := nonce.Hex(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hex1) != 64 {
		t.Fatalf("expected 64 hex chars for 32 bytes, got %d (%s)", len(hex1), hex1)
	}

	hex2, err := nonce.Hex(16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hex2) != 32 {
		t.Fatalf("expected 32 hex chars for 16 bytes, got %d (%s)", len(hex2), hex2)
	}
}

func TestString(t *testing.T) {
	t.Parallel()

	alphabet := "ABCDEF012345"
	str, err := nonce.String(10, alphabet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(str) != 10 {
		t.Fatalf("expected length 10, got %d", len(str))
	}
	for _, ch := range str {
		if !strings.ContainsRune(alphabet, ch) {
			t.Fatalf("character %q not in alphabet %q", ch, alphabet)
		}
	}

	empty, err := nonce.String(0, alphabet)
	if err != nil || empty != "" {
		t.Fatalf("expected empty string for n=0, got %q, err %v", empty, err)
	}
}
