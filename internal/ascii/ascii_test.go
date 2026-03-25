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

	"github.com/stretchr/testify/assert"

	"github.com/deep-rent/nexus/internal/ascii"
)

func TestIsUpper(t *testing.T) {
	tests := []struct {
		name string
		in   rune
		want bool
	}{
		{"lower bound", 'A', true},
		{"upper bound", 'Z', true},
		{"mid range", 'M', true},
		{"just before A", '@', false},
		{"just after Z", '[', false},
		{"lowercase", 'a', false},
		{"digit", '5', false},
		{"symbol", '$', false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ascii.IsUpper(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIsLower(t *testing.T) {
	tests := []struct {
		name string
		in   rune
		want bool
	}{
		{"lower bound", 'a', true},
		{"upper bound", 'z', true},
		{"mid range", 'm', true},
		{"just before a", '`', false},
		{"just after z", '{', false},
		{"uppercase", 'A', false},
		{"digit", '5', false},
		{"symbol", '$', false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ascii.IsLower(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIsDigit(t *testing.T) {
	tests := []struct {
		name string
		in   rune
		want bool
	}{
		{"lower bound", '0', true},
		{"upper bound", '9', true},
		{"mid range", '5', true},
		{"just before 0", '/', false},
		{"just after 9", ':', false},
		{"letter", 'a', false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ascii.IsDigit(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIsAlpha(t *testing.T) {
	tests := []struct {
		name string
		in   rune
		want bool
	}{
		{"uppercase", 'G', true},
		{"lowercase", 'g', true},
		{"digit", '1', false},
		{"symbol", '-', false},
		{"space", ' ', false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ascii.IsAlpha(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIsAlphaNum(t *testing.T) {
	tests := []struct {
		name string
		in   rune
		want bool
	}{
		{"uppercase", 'G', true},
		{"lowercase", 'g', true},
		{"digit", '7', true},
		{"symbol", '-', false},
		{"underscore", '_', false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ascii.IsAlphaNum(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIsWord(t *testing.T) {
	tests := []struct {
		name string
		in   rune
		want bool
	}{
		{"uppercase", 'X', true},
		{"lowercase", 'y', true},
		{"digit", '2', true},
		{"underscore", '_', true},
		{"hyphen", '-', false},
		{"space", ' ', false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ascii.IsWord(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIsSlug(t *testing.T) {
	tests := []struct {
		name string
		in   rune
		want bool
	}{
		{"uppercase", 'X', true},
		{"lowercase", 'y', true},
		{"digit", '2', true},
		{"hyphen", '-', true},
		{"underscore", '_', false},
		{"space", ' ', false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ascii.IsSlug(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestToLower(t *testing.T) {
	tests := []struct {
		name string
		in   rune
		want rune
	}{
		{"uppercase A", 'A', 'a'},
		{"uppercase Z", 'Z', 'z'},
		{"already lowercase", 'g', 'g'},
		{"digit", '5', '5'},
		{"symbol", '#', '#'},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ascii.ToLower(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestToUpper(t *testing.T) {
	tests := []struct {
		name string
		in   rune
		want rune
	}{
		{"lowercase a", 'a', 'A'},
		{"lowercase z", 'z', 'Z'},
		{"already uppercase", 'G', 'G'},
		{"digit", '5', '5'},
		{"symbol", '#', '#'},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ascii.ToUpper(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}
