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

package valid_test

import (
	"testing"

	"uuid"

	"github.com/deep-rent/nexus/valid"
)

type test struct {
	name string
	give string
	want bool
}

func run(t *testing.T, fn func(string) bool, tests []test) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := fn(tt.give), tt.want; got != want {
				t.Errorf("for %q: got %v; want %v", tt.give, got, want)
			}
		})
	}
}

func TestCIDR(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"ipv4", "192.168.1.0/24", true},
		{"ipv6", "2001:db8::/32", true},
		{"missing mask", "192.168.1.0", false},
		{"invalid ip", "not-an-ip/24", false},
	}
	run(t, valid.CIDR, tests)
}

func TestCIDRv4(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid ipv4", "192.168.1.0/24", true},
		{"invalid ipv6", "2001:db8::/32", false},
		{"missing mask", "192.168.1.0", false},
	}
	run(t, valid.CIDRv4, tests)
}

func TestCIDRv6(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid ipv6", "2001:db8::/32", true},
		{"invalid ipv4", "192.168.1.0/24", false},
		{"missing mask", "2001:db8::", false},
	}
	run(t, valid.CIDRv6, tests)
}

func TestHostname(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid standard", "example.com", true},
		{"valid subdomain", "sub.example.com", true},
		{"invalid start char", "-example.com", false},
		{"empty", "", false},
	}
	run(t, valid.Hostname, tests)
}

func TestPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		give int
		want bool
	}{
		{"min valid", 1, true},
		{"max valid", 65535, true},
		{"zero", 0, false},
		{"negative", -1, false},
		{"too large", 65536, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := valid.Port(tt.give), tt.want; got != want {
				t.Errorf("for port %d: got %v; want %v", tt.give, got, want)
			}
		})
	}
}

func TestIP(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid ipv4", "192.168.1.1", true},
		{"valid ipv6", "2001:db8::1", true},
		{"invalid", "not-ip", false},
	}
	run(t, valid.IP, tests)
}

func TestIPv4(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid ipv4", "192.168.1.1", true},
		{"invalid ipv6", "2001:db8::1", false},
		{"invalid", "not-ip", false},
	}
	run(t, valid.IPv4, tests)
}

func TestIPv6(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid ipv6", "2001:db8::1", true},
		{"invalid ipv4", "192.168.1.1", false},
		{"invalid", "not-ip", false},
	}
	run(t, valid.IPv6, tests)
}

func TestFQDN(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid", "example.com", true},
		{"valid trailing dot", "example.com.", true},
		{"invalid no tld", "example", false},
		{"empty", "", false},
	}
	run(t, valid.FQDN, tests)
}

func TestURI(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid url", "https://example.com", true},
		{"valid urn", "urn:isbn:0451450523", true},
		{"invalid", "::bad::", false},
	}
	run(t, valid.URI, tests)
}

func TestURL(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid", "https://example.com", true},
		{"invalid missing scheme", "example.com", false},
		{"empty", "", false},
	}
	run(t, valid.URL, tests)
}

func TestURN(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid", "urn:isbn:0451450523", true},
		{"invalid missing urn", "isbn:0451450523", false},
		{"empty", "", false},
	}
	run(t, valid.URN, tests)
}

func TestAlpha(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid mixed", "abcABC", true},
		{"invalid with numbers", "abc1", false},
		{"invalid with spaces", "abc ABC", false},
		{"empty", "", true},
	}
	run(t, valid.Alpha, tests)
}

func TestAlphaNum(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid mixed", "abc123XYZ", true},
		{"invalid special char", "abc-123", false},
		{"empty", "", true},
	}
	run(t, valid.AlphaNum, tests)
}

func TestASCII(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid standard", "abc123-!", true},
		{"invalid non-ascii", "abc€", false},
		{"empty", "", true},
	}
	run(t, valid.ASCII, tests)
}

func TestSlug(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid", "a-b", true},
		{"invalid uppercase", "A-b", false},
		{"invalid start hyphen", "-a", false},
		{"invalid end hyphen", "a-", false},
		{"invalid consecutive hyphens", "a--b", false},
		{"empty", "", false},
	}
	run(t, valid.Slug, tests)
}

func TestUpper(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid", "ABC", true},
		{"invalid mixed", "ABc", false},
		{"invalid numbers", "ABC1", false},
		{"empty", "", true},
	}
	run(t, valid.Upper, tests)
}

func TestLower(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid", "abc", true},
		{"invalid mixed", "abC", false},
		{"invalid numbers", "abc1", false},
		{"empty", "", true},
	}
	run(t, valid.Lower, tests)
}

func TestBase64(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid block", "YWJj", true},
		{"valid padding", "YWI=", true},
		{"invalid no padding", "YWI", false},
		{"invalid chars", "YWI!", false},
		{"empty", "", true},
	}
	run(t, valid.Base64, tests)
}

func TestBase64URL(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid safe chars", "YWI-_", true},
		{"valid no padding", "YWI", true},
		{"valid padding", "YWI=", true},
		{"invalid base64 chars", "YWI+", false},
		{"empty", "", true},
	}
	run(t, valid.Base64URL, tests)
}

func TestMAC(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid standard", "00:00:5e:00:53:01", true},
		{"valid dashed", "00-00-5e-00-53-01", true},
		{"invalid", "not-a-mac", false},
		{"empty", "", false},
	}
	run(t, valid.MAC, tests)
}

func TestLang(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid simple", "en", true},
		{"valid standard", "en-US", true},
		{"valid complex", "zh-Hant-CN", true},
		{"invalid underscore", "en_US", false},
		{"empty", "", false},
	}
	run(t, valid.Lang, tests)
}

func TestJSON(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid object", `{"a": 1}`, true},
		{"valid array", `[1, "two", true]`, true},
		{"valid scalar", `"string"`, true},
		{"invalid structure", `{a: 1}`, false},
		{"empty", "", false},
	}
	run(t, valid.JSON, tests)
}

func TestMIME(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid simple", "application/json", true},
		{"valid with parameters", "text/html; charset=utf-8", true},
		{"invalid missing subtype", "text", false},
		{"empty", "", false},
	}
	run(t, valid.MIME, tests)
}

func TestCreditCard(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid luhn", "4242424242424242", true},
		{"valid with spaces", "4242 4242 4242 4242", true},
		{"valid with hyphens", "4242-4242-4242-4242", true},
		{"invalid luhn", "4242424242424243", false},
		{"invalid length", "424242424242", false},
		{"invalid chars", "424242424242424a", false},
	}
	run(t, valid.CreditCard, tests)
}

func TestEmail(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid standard", "user@example.com", true},
		{"valid tagged", "user+tag@example.com", true},
		{"valid intranet", "user@example", true},
		{"invalid missing domain", "user@", false},
		{"invalid missing user", "@example.com", false},
		{"empty", "", false},
	}
	run(t, valid.Email, tests)
}

func TestHex(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid plain", "1a", true},
		{"valid prefixed", "0x1A", true},
		{"invalid chars", "1g", false},
		{"empty", "", true},
	}
	run(t, valid.Hex, tests)
}

func TestHexColor(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid 8 char", "#ffffffff", true},
		{"valid 6 char", "#ffffff", true},
		{"valid 4 char", "#ffff", true},
		{"valid 3 char", "#fff", true},
		{"valid no prefix", "ffffff", true},
		{"invalid length", "#fffff", false},
		{"invalid chars", "#gggggg", false},
	}
	run(t, valid.HexColor, tests)
}

func TestISSN(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid", "0378-5955", true},
		{"valid X checksum", "2434-561X", true},
		{"invalid missing hyphen", "03785955", false},
		{"invalid length", "0378-595", false},
		{"invalid checksum", "0378-5954", false},
	}
	run(t, valid.ISSN, tests)
}

func TestISBN10(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid standard", "0-306-40615-2", true},
		{"valid no hyphens", "0306406152", true},
		{"valid X checksum", "0-8044-2957-X", true},
		{"invalid length", "0-306-40615", false},
		{"invalid checksum char", "0-306-40615-Y", false},
		{"invalid checksum", "0-306-40615-3", false},
	}
	run(t, valid.ISBN10, tests)
}

func TestISBN13(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid standard", "978-3-16-148410-0", true},
		{"valid no hyphens", "9783161484100", true},
		{"invalid length", "978-3-16-148410", false},
		{"invalid X checksum", "978-3-16-148410-X", false},
		{"invalid checksum", "978-3-16-148410-1", false},
	}
	run(t, valid.ISBN13, tests)
}

func TestISBN(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid 10", "0-306-40615-2", true},
		{"valid 13", "978-3-16-148410-0", true},
		{"invalid format", "bad", false},
	}
	run(t, valid.ISBN, tests)
}

func TestCountry2(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid", "US", true},
		{"invalid lowercase", "us", false},
		{"invalid length", "USA", false},
	}
	run(t, valid.Country2, tests)
}

func TestCountry3(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid", "USA", true},
		{"invalid lowercase", "usa", false},
		{"invalid length", "US", false},
	}
	run(t, valid.Country3, tests)
}

func TestCountryN(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid", "840", true},
		{"invalid length", "84", false},
		{"invalid chars", "84a", false},
	}
	run(t, valid.CountryN, tests)
}

func TestCurrency(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid", "USD", true},
		{"invalid lowercase", "usd", false},
		{"invalid length", "US", false},
	}
	run(t, valid.Currency, tests)
}

func TestUUID(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid v4", uuid.NewV4().String(), true},
		{"valid v7", uuid.NewV7().String(), true},
		{"invalid", "018e6-123", false},
	}
	run(t, valid.UUID, tests)
}

func TestLat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		give float32
		want bool
	}{
		{"zero", 0.0, true},
		{"max valid", 90.0, true},
		{"min valid", -90.0, true},
		{"over max", 91.0, false},
		{"under min", -91.0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := valid.Lat(tt.give), tt.want; got != want {
				t.Errorf("for latitude %f: got %v; want %v", tt.give, got, want)
			}
		})
	}
}

func TestLon(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		give float32
		want bool
	}{
		{"zero", 0.0, true},
		{"max valid", 180.0, true},
		{"min valid", -180.0, true},
		{"over max", 181.0, false},
		{"under min", -181.0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := valid.Lon(tt.give), tt.want; got != want {
				t.Errorf(
					"for longitude %f: got %v; want %v",
					tt.give,
					got,
					want,
				)
			}
		})
	}
}

func TestMD5(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid", "d41d8cd98f00b204e9800998ecf8427e", true},
		{"invalid length", "d41d8cd98f00b204e9800998ecf8427", false},
		{"invalid chars", "d41d8cd98f00b204e9800998ecf8427z", false},
	}
	run(t, valid.MD5, tests)
}

func TestSHA256(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b9" +
			"34ca495991b7852b855", true},
		{"invalid length", "e3b0c44298fc1c149afbf4c8996fb92427ae41e46", false},
	}
	run(t, valid.SHA256, tests)
}

func TestSHA384(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0" +
			"7434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", true},
		{"invalid length", "38b060a751ac96384cd9327eb1b1e36a21fdb7111", false},
	}
	run(t, valid.SHA384, tests)
}

func TestSHA512(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83" +
			"f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd4" +
			"7417a81a538327af927da3e", true},
		{"invalid length", "cf83e1357eefb8bdf1542850d66d8007d620e4050", false},
	}
	run(t, valid.SHA512, tests)
}

func TestSemVer(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid prefixed", "v1.2.3", true},
		{"invalid unprefixed", "1.2.3", false},
		{"valid pre-release", "v1.2.3-alpha.1+build", true},
		{"valid no patch", "v1.2", true},
		{"valid no minor", "v1", true},
		{"empty", "", false},
	}
	run(t, valid.SemVer, tests)
}

func TestPhone(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid standard", "+1234567890", true},
		{"valid max length", "+123456789012345", true},
		{"invalid missing plus", "1234567890", false},
		{"invalid too short", "+1", false},
		{"invalid too long", "+1234567890123456", false},
	}
	run(t, valid.Phone, tests)
}

func TestBIC(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid short", "SBANDE21", true},
		{"valid long", "SBANDE21XXX", true},
		{"invalid length", "SBANDE21XX", false},
		{"invalid format", "SBANDE21!!!", false},
	}
	run(t, valid.BIC, tests)
}

func TestIBAN(t *testing.T) {
	t.Parallel()
	tests := []test{
		{"valid standard", "DE89370400440532013000", true},
		{"valid spaced", "DE89 3704 0044 0532 0130 00", true},
		{"invalid checksum", "DE89370400440532013001", false},
		{"invalid length", "DE8937040044053201300", false},
		{"invalid chars", "DE8937040044053201300!", false},
	}
	run(t, valid.IBAN, tests)
}

// Every character-class predicate rejects the empty string. This is the
// package convention, and the shared basis makes it uniform.
func TestCharacterClasses_AcceptEmpty(t *testing.T) {
	t.Parallel()

	fns := map[string]func(string) bool{
		"Alpha":     valid.Alpha,
		"AlphaNum":  valid.AlphaNum,
		"ASCII":     valid.ASCII,
		"Upper":     valid.Upper,
		"Lower":     valid.Lower,
		"Hex":       valid.Hex,
		"Base64":    valid.Base64,
		"Base64URL": valid.Base64URL,
	}

	for name, fn := range fns {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if !fn("") {
				t.Errorf("%s(%q) = false; want true", name, "")
			}
		})
	}
}
