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

// classes pairs each classification function with a label so the whole suite
// can be swept over the full ASCII range in one benchmark.
var classes = []struct {
	name string
	fn   func(byte) bool
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
	for _, cl := range classes {
		b.Run(cl.name, func(b *testing.B) {
			var acc bool
			for i := 0; i < b.N; i++ {
				acc = cl.fn(byte(i))
			}
			_ = acc
		})
	}
}

// benchText is a representative mixed-case ASCII string for the string-level
// benchmarks.
const benchText = "The Quick Brown Fox Jumps Over The Lazy Dog! 0123456789"

func BenchmarkEqualFold(b *testing.B) {
	// Fold benchText against an all-uppercase copy: the strings are equal under
	// EqualFold, so every byte is compared (the worst case).
	upper := ascii.ToUpper(benchText)

	var acc bool
	for b.Loop() {
		acc = ascii.EqualFold(benchText, upper)
	}
	_ = acc
}

func BenchmarkToLower(b *testing.B) {
	// "convert" allocates and rewrites; "nop" takes the fast path that returns
	// the input unchanged when it already contains no uppercase letters.
	lower := ascii.ToLower(benchText)
	benches := []struct {
		name string
		give string
	}{
		{"convert", benchText},
		{"nop", lower},
	}
	for _, bb := range benches {
		b.Run(bb.name, func(b *testing.B) {
			var acc string
			for i := 0; i < b.N; i++ {
				acc = ascii.ToLower(bb.give)
			}
			_ = acc
		})
	}
}

func BenchmarkToUpper(b *testing.B) {
	// "convert" allocates and rewrites; "nop" takes the fast path that returns
	// the input unchanged when it already contains no lowercase letters.
	upper := ascii.ToUpper(benchText)
	benches := []struct {
		name string
		give string
	}{
		{"convert", benchText},
		{"nop", upper},
	}
	for _, bb := range benches {
		b.Run(bb.name, func(b *testing.B) {
			var acc string
			for i := 0; i < b.N; i++ {
				acc = ascii.ToUpper(bb.give)
			}
			_ = acc
		})
	}
}
