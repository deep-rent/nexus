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

package pkce_test

import (
	"testing"

	"github.com/deep-rent/nexus/sec/iam/oauth/pkce"
)

func BenchmarkVerify(b *testing.B) {
	v, _ := pkce.Verifier(b.Context())
	c, _ := pkce.Challenge(v, pkce.MethodS256)

	for b.Loop() {
		pkce.Verify(v, c, pkce.MethodS256)
	}
}

func BenchmarkVerifier(b *testing.B) {
	for b.Loop() {
		_, _ = pkce.Verifier(b.Context())
	}
}
