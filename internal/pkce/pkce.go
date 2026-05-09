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

package pkce

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

const (
	MethodS256  = "S256"
	MethodPlain = "plain"
)

func Supports(method string) bool {
	return method == MethodS256 || method == MethodPlain
}

// Verify validates an incoming code verifier against the originally stored
// challenge.
func Verify(verifier, challenge, method string) bool {
	if len(challenge) == 0 {
		return false
	}

	var exp []byte
	switch method {
	case MethodS256:
		sum := sha256.Sum256([]byte(verifier))
		enc := base64.RawURLEncoding.EncodeToString(sum[:])
		exp = []byte(enc)
	case MethodPlain:
		exp = []byte(verifier)
	default:
		return false
	}

	// Ensure constant-time comparison doesn't panic due to unequal lengths.
	if len(exp) != len(challenge) {
		return false
	}

	return subtle.ConstantTimeCompare(exp, []byte(challenge)) == 1
}
