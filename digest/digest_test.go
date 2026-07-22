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

package digest_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/deep-rent/nexus/digest"
)

func TestString(t *testing.T) {
	t.Parallel()

	input := "secret-auth-token-12345"
	d1 := digest.String(input)

	sum := sha256.Sum256([]byte(input))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])

	if d1 != expected {
		t.Fatalf("expected digest %s, got %s", expected, d1)
	}
}

func TestBytes(t *testing.T) {
	t.Parallel()

	input := []byte("secret-auth-token-12345")
	d1 := digest.Bytes(input)
	d2 := digest.String("secret-auth-token-12345")

	if d1 != d2 {
		t.Fatalf("expected Bytes and String digests to match, got %s vs %s", d1, d2)
	}
}

func TestEqual(t *testing.T) {
	t.Parallel()

	d1 := digest.String("token-A")
	d2 := digest.String("token-A")
	d3 := digest.String("token-B")

	if !digest.Equal(d1, d2) {
		t.Fatal("expected Equal to return true for identical digests")
	}

	if digest.Equal(d1, d3) {
		t.Fatal("expected Equal to return false for different digests")
	}
}
