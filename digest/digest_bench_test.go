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
	"strings"
	"testing"

	"github.com/deep-rent/nexus/digest"
)

func BenchmarkHasherString(b *testing.B) {
	h := digest.New(nil)
	v := strings.Repeat("x", 32)
	b.ReportAllocs()
	for b.Loop() {
		_ = h.String(v)
	}
}

func BenchmarkHasherBytes(b *testing.B) {
	h := digest.New(nil)
	v := []byte(strings.Repeat("x", 32))
	b.ReportAllocs()
	for b.Loop() {
		_ = h.Bytes(v)
	}
}

func BenchmarkHasherMatch(b *testing.B) {
	h := digest.New(nil)
	v := strings.Repeat("x", 32)
	d := h.String(v)
	b.ReportAllocs()
	for b.Loop() {
		_ = h.Match(v, d)
	}
}
