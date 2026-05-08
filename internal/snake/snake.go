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

// Package snake provides functions for converting strings between camelCase and
// snake_case formats.
//
// It handles transitions between lowercase letters, uppercase letters, and
// digits to produce idiomatic snake_case or SCREAMING_SNAKE_CASE strings. The
// implementation is specifically tuned for ASCII character sets and manages
// acronyms by detecting transitions from sequences of uppercase letters to a
// new word.
//
// # Usage
//
// Use [ToLower] for standard snake_case and [ToUpper] for constant-style
// uppercase snake_case.
//
// Example:
//
//	low := snake.ToLower("JSONData") // "json_data"
//	up  := snake.ToUpper("myVariable") // "MY_VARIABLE"
package snake

import (
	"strings"

	"github.com/deep-rent/nexus/internal/ascii"
)

// ToUpper converts a camelCase string to an uppercase SNAKE_CASE string.
//
// For example, "fooBar" is converted to "FOO_BAR", and so is "FOOBar". Note
// that digits do not induce transitions, so "foo1" becomes "FOO1". Only ASCII
// characters are supported. This function internally uses [transform] with
// [ascii.ToUpper].
func ToUpper(s string) string { return transform(s, ascii.ToUpper) }

// ToLower converts a camelCase string to a lowercase snake_case string.
//
// For example, "fooBar" is converted to "foo_bar", and so is "FOOBar". Note
// that digits do not induce transitions, so "foo1" becomes "foo1". Only ASCII
// characters are supported. This function internally uses [transform] with
// [ascii.ToLower].
func ToLower(s string) string { return transform(s, ascii.ToLower) }

// transform is a helper function that performs the actual text conversion.
//
// It iterates through the runes of the string s and applies the toCase
// function to each character, while injecting underscores at word boundaries
// detected by case transitions or acronym detection logic.
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
