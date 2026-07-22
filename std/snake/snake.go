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

package snake

import (
	"strings"

	"github.com/deep-rent/nexus/std/ascii"
)

// ToUpper converts a camelCase string to an uppercase SNAKE_CASE string.
//
// For example, "fooBar" is converted to "FOO_BAR", and so is "FOOBar". Note
// that digits do not induce transitions, so "foo1" becomes "FOO1". Only ASCII
// characters are supported. This function internally uses [transform] with
// [ascii.Upper].
func ToUpper(s string) string { return transform(s, ascii.Upper) }

// ToLower converts a camelCase string to a lowercase snake_case string.
//
// For example, "fooBar" is converted to "foo_bar", and so is "FOOBar". Note
// that digits do not induce transitions, so "foo1" becomes "foo1". Only ASCII
// characters are supported. This function internally uses [transform] with
// [ascii.Lower].
func ToLower(s string) string { return transform(s, ascii.Lower) }

// transform is a helper function that performs the actual text conversion.
//
// It iterates through the bytes of the string s and applies the toCase
// function to each character, while injecting underscores at word boundaries
// detected by case transitions or acronym detection logic. Non-ASCII bytes
// pass through unchanged, so multi-byte UTF-8 runes are preserved verbatim.
func transform(s string, toCase func(byte) byte) string {
	var b strings.Builder
	b.Grow(len(s) + 5)
	for i := 0; i < len(s); i++ {
		c := s[i]
		// Insert an underscore before a capital letter or digit.
		if i != 0 {
			q := s[i-1]
			if (ascii.IsLower(q) &&
				// Case 1: Lowercase to uppercase/digit transition ("myVar",
				// "myVar1").
				(ascii.IsUpper(c) || ascii.IsDigit(c))) ||
				(ascii.IsUpper(q) &&
					// Case 2: Acronym to new word transition ("MYVar").
					ascii.IsUpper(c) &&
					i+1 < len(s) &&
					ascii.IsLower(s[i+1])) {
				b.WriteByte('_')
			}
		}
		b.WriteByte(toCase(c))
	}
	return b.String()
}
