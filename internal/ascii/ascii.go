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

package ascii

func IsUpper(c rune) bool {
	return c >= 'A' && c <= 'Z'
}

func IsLower(c rune) bool {
	return c >= 'a' && c <= 'z'
}

func IsDigit(c rune) bool {
	return c >= '0' && c <= '9'
}

func IsAlpha(c rune) bool {
	return IsUpper(c) || IsLower(c)
}

func IsAlphaNum(c rune) bool {
	return IsAlpha(c) || IsDigit(c)
}

func IsWord(c rune) bool {
	return IsAlphaNum(c) || c == '_'
}

func IsSlug(c rune) bool {
	return IsAlphaNum(c) || c == '-'
}
