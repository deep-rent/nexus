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

	"github.com/deep-rent/nexus/internal/ascii"
)

func TestIsUpper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give rune
		want bool
	}{
		{"lower bound", 'A', true},
		{"upper bound", 'Z', true},
		{"mid range", 'M', true},
		{"just before a", '@', false},
		{"just after z", '[', false},
		{"lowercase", 'a', false},
		{"digit", '5', false},
		{"symbol", '$', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.IsUpper(tt.give), tt.want; got != want {
				t.Errorf("IsUpper(%q) = %v; want %v", tt.give, got, want)
			}
		})
	}
}

func TestIsLower(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give rune
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.IsLower(tt.give), tt.want; got != want {
				t.Errorf("IsLower(%q) = %v; want %v", tt.give, got, want)
			}
		})
	}
}

func TestIsDigit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give rune
		want bool
	}{
		{"lower bound", '0', true},
		{"upper bound", '9', true},
		{"mid range", '5', true},
		{"just before 0", '/', false},
		{"just after 9", ':', false},
		{"letter", 'a', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.IsDigit(tt.give), tt.want; got != want {
				t.Errorf("IsDigit(%q) = %v; want %v", tt.give, got, want)
			}
		})
	}
}

func TestIsAlpha(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give rune
		want bool
	}{
		{"uppercase", 'G', true},
		{"lowercase", 'g', true},
		{"digit", '1', false},
		{"symbol", '-', false},
		{"space", ' ', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.IsAlpha(tt.give), tt.want; got != want {
				t.Errorf("IsAlpha(%q) = %v; want %v", tt.give, got, want)
			}
		})
	}
}

func TestIsAlphaNum(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give rune
		want bool
	}{
		{"uppercase", 'G', true},
		{"lowercase", 'g', true},
		{"digit", '7', true},
		{"symbol", '-', false},
		{"underscore", '_', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.IsAlphaNum(tt.give), tt.want; got != want {
				t.Errorf("IsAlphaNum(%q) = %v; want %v", tt.give, got, want)
			}
		})
	}
}

func TestIsWord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give rune
		want bool
	}{
		{"uppercase", 'X', true},
		{"lowercase", 'y', true},
		{"digit", '2', true},
		{"underscore", '_', true},
		{"hyphen", '-', false},
		{"space", ' ', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.IsWord(tt.give), tt.want; got != want {
				t.Errorf("IsWord(%q) = %v; want %v", tt.give, got, want)
			}
		})
	}
}

func TestIsSlug(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give rune
		want bool
	}{
		{"uppercase", 'X', true},
		{"lowercase", 'y', true},
		{"digit", '2', true},
		{"hyphen", '-', true},
		{"underscore", '_', false},
		{"space", ' ', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.IsSlug(tt.give), tt.want; got != want {
				t.Errorf("IsSlug(%q) = %v; want %v", tt.give, got, want)
			}
		})
	}
}

func TestToLower(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give rune
		want rune
	}{
		{"uppercase a", 'A', 'a'},
		{"uppercase z", 'Z', 'z'},
		{"already lowercase", 'g', 'g'},
		{"digit", '5', '5'},
		{"symbol", '#', '#'},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.ToLower(tt.give), tt.want; got != want {
				t.Errorf("ToLower(%q) = %q; want %q", tt.give, got, want)
			}
		})
	}
}

func TestToUpper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give rune
		want rune
	}{
		{"lowercase a", 'a', 'A'},
		{"lowercase z", 'z', 'Z'},
		{"already uppercase", 'G', 'G'},
		{"digit", '5', '5'},
		{"symbol", '#', '#'},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.ToUpper(tt.give), tt.want; got != want {
				t.Errorf("ToUpper(%q) = %q; want %q", tt.give, got, want)
			}
		})
	}
}
