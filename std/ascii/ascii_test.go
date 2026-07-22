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
	"strings"
	"testing"

	"github.com/deep-rent/nexus/std/ascii"
)

func TestConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
		want byte
	}{
		{"NUL", ascii.NUL, 0x00},
		{"BEL", ascii.BEL, '\a'},
		{"BS", ascii.BS, '\b'},
		{"HT", ascii.HT, '\t'},
		{"LF", ascii.LF, '\n'},
		{"VT", ascii.VT, '\v'},
		{"FF", ascii.FF, '\f'},
		{"CR", ascii.CR, '\r'},
		{"ESC", ascii.ESC, 0x1B},
		{"US", ascii.US, 0x1F},
		{"SP", ascii.SP, ' '},
		{"DEL", ascii.DEL, 0x7F},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := tt.give, tt.want; got != want {
				t.Errorf("got %#x; want %#x", got, want)
			}
		})
	}
}

func TestIsUpper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
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
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestIsLower(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
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
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestIsDigit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
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
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestIsHex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
		want bool
	}{
		{"digit", '0', true},
		{"digit nine", '9', true},
		{"lower a", 'a', true},
		{"lower f", 'f', true},
		{"upper A", 'A', true},
		{"upper F", 'F', true},
		{"just after f", 'g', false},
		{"just after F", 'G', false},
		{"symbol", '#', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.IsHex(tt.give), tt.want; got != want {
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

// TestClassificationEquivalence cross-checks each classifier against an
// explicit alphabet of every character it should accept. Sweeping all 256 byte
// values against these alphabets (including the non-ASCII range 0x80–0xFF)
// guards the lookup table against typos.
func TestClassificationEquivalence(t *testing.T) {
	t.Parallel()

	const (
		upper     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lower     = "abcdefghijklmnopqrstuvwxyz"
		digit     = "0123456789"
		hexDig    = digit + "abcdef" + "ABCDEF"
		punct     = `!"#%&'()*,-./:;?@[\]_{}`
		symbol    = "$+<=>^`|~"
		space     = " \t\n\v\f\r"
		graph     = upper + lower + digit + punct + symbol // 0x21–0x7E
		printable = graph + " "                            // 0x20–0x7E
		// Control characters: the C0 set (0x00–0x1F) and DEL (0x7F).
		control = "\x00\x01\x02\x03\x04\x05\x06\a\b\t\n\v\f\r\x0e\x0f" +
			"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" +
			"\x7f"
	)

	classes := []struct {
		name  string
		got   func(byte) bool
		valid string // every character the classifier must accept
	}{
		{"IsUpper", ascii.IsUpper, upper},
		{"IsLower", ascii.IsLower, lower},
		{"IsDigit", ascii.IsDigit, digit},
		{"IsAlpha", ascii.IsAlpha, upper + lower},
		{"IsAlphaNum", ascii.IsAlphaNum, upper + lower + digit},
		{"IsHex", ascii.IsHex, hexDig},
		{"IsSpace", ascii.IsSpace, space},
		{"IsPrint", ascii.IsPrint, printable},
		{"IsControl", ascii.IsControl, control},
		{"IsPunct", ascii.IsPunct, punct},
		{"IsSymbol", ascii.IsSymbol, symbol},
		{"IsGraph", ascii.IsGraph, graph},
	}

	for _, c := range classes {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			for i := 0; i <= 0xFF; i++ {
				b := byte(i)
				want := strings.IndexByte(c.valid, b) >= 0
				if got := c.got(b); got != want {
					t.Errorf("%s(%#x) = %v; want %v", c.name, b, got, want)
				}
			}
		})
	}
}

func TestIsAlpha(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
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
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestIsAlphaNum(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
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
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestIsWord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
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
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestIsSlug(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
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
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestIsPunct(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
		want bool
	}{
		{"exclamation", '!', true},
		{"at", '@', true},
		{"underscore", '_', true},
		{"backslash", '\\', true},
		{"brace", '{', true},
		{"dollar symbol", '$', false},
		{"tilde symbol", '~', false},
		{"letter", 'a', false},
		{"digit", '5', false},
		{"space", ' ', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.IsPunct(tt.give), tt.want; got != want {
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestIsSymbol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
		want bool
	}{
		{"dollar", '$', true},
		{"plus", '+', true},
		{"equals", '=', true},
		{"caret", '^', true},
		{"backtick", '`', true},
		{"pipe", '|', true},
		{"tilde", '~', true},
		{"exclamation punct", '!', false},
		{"letter", 'a', false},
		{"digit", '5', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.IsSymbol(tt.give), tt.want; got != want {
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestIsGraph(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
		want bool
	}{
		{"exclamation", '!', true},
		{"tilde", '~', true},
		{"letter", 'A', true},
		{"digit", '5', true},
		{"symbol", '$', true},
		{"space", ' ', false},
		{"tab", '\t', false},
		{"delete", 0x7F, false},
		{"above ascii", 0x80, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.IsGraph(tt.give), tt.want; got != want {
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestIsSpace(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
		want bool
	}{
		{"space", ' ', true},
		{"tab", '\t', true},
		{"newline", '\n', true},
		{"vertical tab", '\v', true},
		{"form feed", '\f', true},
		{"carriage return", '\r', true},
		{"uppercase a", 'A', false},
		{"digit", '5', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.IsSpace(tt.give), tt.want; got != want {
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestIsPrint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
		want bool
	}{
		{"space", ' ', true},
		{"tilde", '~', true},
		{"letter", 'A', true},
		{"digit", '5', true},
		{"newline", '\n', false},
		{"delete", 0x7F, false},
		{"above ascii", 0x80, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.IsPrint(tt.give), tt.want; got != want {
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestIsControl(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
		want bool
	}{
		{"null", 0x00, true},
		{"newline", '\n', true},
		{"delete", 0x7F, true},
		{"space", ' ', false},
		{"letter", 'A', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.IsControl(tt.give), tt.want; got != want {
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestIsASCII(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
		want bool
	}{
		{"null", 0x00, true},
		{"letter", 'A', true},
		{"delete", 0x7F, true},
		{"above ascii", 0x80, false},
		{"high byte", 0xFF, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.IsASCII(tt.give), tt.want; got != want {
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestLower(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
		want byte
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
			if got, want := ascii.Lower(tt.give), tt.want; got != want {
				t.Errorf("got %q; want %q", got, want)
			}
		})
	}
}

func TestUpper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give byte
		want byte
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
			if got, want := ascii.Upper(tt.give), tt.want; got != want {
				t.Errorf("got %q; want %q", got, want)
			}
		})
	}
}

func TestAll(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		fn   func(byte) bool
		want bool
	}{
		{
			name: "all lowercase true",
			give: "abcdefg",
			fn:   ascii.IsLower,
			want: true,
		},
		{
			name: "all lowercase false",
			give: "abcDefg",
			fn:   ascii.IsLower,
			want: false,
		},
		{
			name: "all digits true",
			give: "12345",
			fn:   ascii.IsDigit,
			want: true,
		},
		{
			name: "all digits false",
			give: "123a45",
			fn:   ascii.IsDigit,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.All(tt.give, tt.fn), tt.want; got != want {
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestEqualFold(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
		t    string
		want bool
	}{
		{"exact match", "hello", "hello", true},
		{"different case", "Hello", "hElLo", true},
		{"all upper vs all lower", "WORLD", "world", true},
		{"different length", "hi", "hii", false},
		{"different content", "hello", "world", false},
		{"numbers match", "123", "123", true},
		{"symbols match", "!@#", "!@#", true},
		{"symbols mismatch", "!@#", "!@$", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := ascii.EqualFold(tt.s, tt.t), tt.want; got != want {
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestToLower(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want string
	}{
		{"all upper", "HELLO", "hello"},
		{"all lower", "hello", "hello"},
		{"mixed case", "HeLlO", "hello"},
		{"with numbers", "HeLlO 123", "hello 123"},
		{"with symbols", "HeLlO!", "hello!"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ascii.ToLower(tt.give); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestToUpper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want string
	}{
		{"all upper", "HELLO", "HELLO"},
		{"all lower", "hello", "HELLO"},
		{"mixed case", "HeLlO", "HELLO"},
		{"with numbers", "hello 123", "HELLO 123"},
		{"with symbols", "hello!", "HELLO!"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ascii.ToUpper(tt.give); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestHasLower(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want bool
	}{
		{"all upper", "HELLO", false},
		{"all lower", "hello", true},
		{"mixed case", "HeLlO", true},
		{"with numbers", "123", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ascii.HasLower(tt.give); got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestHasUpper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want bool
	}{
		{"all upper", "HELLO", true},
		{"all lower", "hello", false},
		{"mixed case", "HeLlO", true},
		{"with numbers", "123", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ascii.HasUpper(tt.give); got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}
