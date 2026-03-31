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

// Package snake provides functions for converting strings between camelCase
// and snake_case formats.
package snake

import (
	"strings"

	"github.com/deep-rent/nexus/internal/ascii"
)

// ToUpper converts a camelCase string to an uppercase SNAKE_CASE string.
//
// For example, "fooBar" is converted to "FOO_BAR", and so is "FOOBar". Note
// that digits do not induce transitions, so "foo1" becomes "FOO1". Only ASCII
// characters are supported.
func ToUpper(s string) string { return transform(s, ascii.ToUpper) }

// ToLower converts a camelCase string to a lowercase snake_case string.
//
// For example, "fooBar" is converted to "foo_bar", and so is "FOOBar". Note
// that digits do not induce transitions, so "foo1" becomes "FOO1". Only ASCII
// characters are supported.
func ToLower(s string) string { return transform(s, ascii.ToLower) }

// transform is a helper function that performs the actual text conversion.
func transform(s string, toCase func(rune) rune) string {
	var b strings.Builder
	b.Grow(len(s) + 5)
	runes := []rune(s)
	for i, r := range runes {
		// Insert an underscore before a capital letter or digit.
		if i != 0 {
			q := runes[i-1]
			if (ascii.IsLower(q) &&
				// Case 1: Lowercase to uppercase/digit transition ("myVar", "myVar1").
				(ascii.IsUpper(r) || ascii.IsDigit(r))) ||
				(ascii.IsUpper(q) &&
					// Case 2: Acronym to new word transition ("MYVar").
					ascii.IsUpper(r) &&
					i+1 < len(runes) &&
					ascii.IsLower(runes[i+1])) {
				b.WriteRune('_')
			}
		}
		b.WriteRune(toCase(r))
	}
	return b.String()
}
