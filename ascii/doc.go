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

// Package ascii provides fast, byte-based classification and conversion
// functions specifically for ASCII characters.
//
// It is designed as a lightweight alternative to the standard [unicode] package
// for cases where only basic ASCII support is required. By focusing strictly on
// the ASCII range, it avoids the overhead of large Unicode lookup tables,
// making it suitable for high-performance parsing and validation tasks.
//
// Operating on individual bytes rather than decoded runes is not a limitation
// for ASCII: every ASCII character encodes to a single byte, and in UTF-8 the
// bytes of a multi-byte rune are all greater than 0x7F, so they are simply
// reported as non-ASCII rather than being misclassified.
//
// # Usage
//
// You can use the classification functions to test bytes or conversion
// functions to shift casing.
//
// Example:
//
//	c := byte('A')
//	if ascii.IsUpper(c) {
//		lower := ascii.Lower(c) // 'a'
//	}
package ascii
