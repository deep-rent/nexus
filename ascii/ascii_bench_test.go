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

package ascii_test

import (
	"testing"

	"github.com/deep-rent/nexus/ascii"
)

// benchClasses pairs each classification function with a label so the whole
// suite can be swept over the full ASCII range in one benchmark.
var benchClasses = []struct {
	name string
	fn   func(rune) bool
}{
	{"IsUpper", ascii.IsUpper},
	{"IsLower", ascii.IsLower},
	{"IsDigit", ascii.IsDigit},
	{"IsAlpha", ascii.IsAlpha},
	{"IsAlphaNum", ascii.IsAlphaNum},
	{"IsHex", ascii.IsHex},
	{"IsSpace", ascii.IsSpace},
	{"IsPrint", ascii.IsPrint},
	{"IsControl", ascii.IsControl},
	{"IsPunct", ascii.IsPunct},
	{"IsSymbol", ascii.IsSymbol},
	{"IsGraph", ascii.IsGraph},
}

func BenchmarkClassify(b *testing.B) {
	for _, cl := range benchClasses {
		b.Run(cl.name, func(b *testing.B) {
			var acc bool
			for i := 0; i < b.N; i++ {
				acc = cl.fn(rune(i & 0x7F))
			}
			_ = acc
		})
	}
}
