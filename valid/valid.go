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

package valid

import (
	"encoding/json/jsontext"
	"mime"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/mod/semver"
	"uuid"

	"github.com/deep-rent/nexus/ascii"
)

// CIDR checks if the string is a valid Classless Inter-Domain Routing (CIDR)
// block. A valid CIDR block is an IP address followed by a slash and a
// prefix length.
func CIDR(s string) bool {
	_, err := netip.ParsePrefix(s)
	return err == nil
}

// CIDRv4 checks if the string is a valid IPv4 CIDR block.
func CIDRv4(s string) bool {
	p, err := netip.ParsePrefix(s)
	return err == nil && p.Addr().Is4()
}

// CIDRv6 checks if the string is a valid IPv6 CIDR block.
func CIDRv6(s string) bool {
	p, err := netip.ParsePrefix(s)
	return err == nil && p.Addr().Is6()
}

// Hostname checks if the string is a valid hostname according to RFC 952 and
// RFC 1123. The hostname must be at most 253 characters long.
func Hostname(s string) bool {
	return len(s) != 0 && len(s) <= 253 && rxHostname.MatchString(s)
}

// Port checks if the number represents a valid network port number.
// Port numbers must be between 1 and 65535 inclusive.
func Port(n int) bool {
	return n > 0 && n <= 65535
}

// IP checks if the string is a valid IP address (either IPv4 or IPv6).
func IP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// IPv4 checks if the string is a valid IPv4 address.
func IPv4(s string) bool {
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.Is4()
}

// IPv6 checks if the string is a valid IPv6 address.
func IPv6(s string) bool {
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.Is6()
}

// FQDN checks if the string is a Fully Qualified Domain Name (FQDN).
// An FQDN must have at least one valid top-level domain. It allows for an
// optional trailing dot.
func FQDN(s string) bool {
	return len(s) != 0 && len(s) <= 253 && rxFQDN.MatchString(s)
}

// URI checks if the string is a valid URI (Uniform Resource Identifier)
// according to RFC 3986.
func URI(s string) bool {
	_, err := url.ParseRequestURI(s)
	return err == nil
}

// URL checks if the string is a valid URL with a scheme and host.
func URL(s string) bool {
	u, err := url.ParseRequestURI(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// URN checks if the string is a valid URN (Uniform Resource Name) according to
// RFC 2141.
func URN(s string) bool {
	return rxURN.MatchString(s)
}

// Alpha checks if the string contains only alphabetical characters (a-z, A-Z).
// An empty string returns true.
func Alpha(s string) bool {
	return ascii.All(s, ascii.IsAlpha)
}

// AlphaNum checks if the string contains only alphanumeric characters (a-z,
// A-Z, 0-9). An empty string returns true.
func AlphaNum(s string) bool {
	return ascii.All(s, ascii.IsAlphaNum)
}

// ASCII checks if the string contains only ASCII characters.
// An empty string returns true.
func ASCII(s string) bool {
	return ascii.All(s, ascii.IsASCII)
}

// Slug checks if the string is a valid URL slug.
// A slug consists of lowercase letters, numbers, and hyphens, and cannot
// start or end with a hyphen or contain consecutive hyphens. Empty strings will
// be rejected.
func Slug(s string) bool {
	if s == "" || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ascii.IsLower(c) || ascii.IsDigit(c) {
			continue
		}
		if c == '-' {
			if s[i-1] == '-' {
				return false
			}
			continue
		}
		return false
	}
	return true
}

// Upper checks if the string contains only uppercase characters (A-Z).
// An empty string returns true.
func Upper(s string) bool {
	return ascii.All(s, ascii.IsUpper)
}

// Lower checks if the string contains only lowercase characters (a-z).
// An empty string returns true.
func Lower(s string) bool {
	return ascii.All(s, ascii.IsLower)
}

// Base64 checks if the string is a valid Base64 encoded string.
// It allows standard padding characters. An empty string returns true.
func Base64(s string) bool {
	return rxBase64.MatchString(s)
}

// Base64URL checks if the string is a valid Base64URL encoded string.
// Padding characters are supported but optional. An empty string returns true.
func Base64URL(s string) bool {
	return rxBase64URL.MatchString(s)
}

// MAC checks if the string is a valid IEEE 802 MAC address.
func MAC(s string) bool {
	_, err := net.ParseMAC(s)
	return err == nil
}

// Lang checks if the string is a valid BCP 47 language tag.
// It strictly follows RFC 5646.
func Lang(s string) bool {
	return rxBCP47.MatchString(s)
}

// JSON checks if the string is a valid JSON document.
// It performs the check efficiently.
func JSON(s string) bool {
	return jsontext.Value(s).IsValid()
}

// MIME checks if the string is a valid Media Type (MIME type) according to
// RFC 2045 and RFC 2046.
func MIME(s string) bool {
	t, _, err := mime.ParseMediaType(s)
	return err == nil && strings.Contains(t, "/")
}

// CreditCard checks if the string is a valid credit card number using the Luhn
// algorithm. It ignores whitespace and hyphens before calculating the checksum.
func CreditCard(s string) bool {
	var (
		sum int
		cnt int
		alt bool
	)
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c == ' ' || c == '-' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		n := int(c - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		cnt++
		alt = !alt
	}
	return cnt >= 13 && cnt <= 19 && sum%10 == 0
}

// Email checks if the string is a valid email address according to the W3C
// HTML5 specification.
func Email(s string) bool {
	return rxEmail.MatchString(s)
}

// Hex checks if the string is a valid hexadecimal number.
// The string may optionally be prefixed with "0x" or "0X".
func Hex(s string) bool {
	if len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	return ascii.All(s, ascii.IsHex)
}

// HexColor checks if the string is a valid hex color code.
// The string may optionally be prefixed with "#". It must be exactly 3, 4, 6,
// or 8 hexadecimal characters long, covering the RGB, RGBA, RRGGBB, and
// RRGGBBAA notations.
func HexColor(s string) bool {
	if len(s) > 0 && s[0] == '#' {
		s = s[1:]
	}
	switch len(s) {
	case 3, 4, 6, 8:
		return ascii.All(s, ascii.IsHex)
	default:
		return false
	}
}

// ISSN checks if the string is a valid International Standard Serial Number
// (ISSN).
func ISSN(s string) bool {
	if len(s) != 9 || s[4] != '-' {
		return false
	}
	var sum int
	weight := 8
	for i := range 8 {
		if i == 4 {
			continue
		}
		c := s[i]
		if !ascii.IsDigit(c) {
			return false
		}
		sum += int(c-'0') * weight
		weight--
	}

	c := s[8]
	if c == 'X' {
		sum += 10
	} else if ascii.IsDigit(c) {
		sum += int(c - '0')
	} else {
		return false
	}
	return sum%11 == 0
}

// ISBN10 checks if the string is a valid ISBN-10.
// It strips hyphens before validation.
func ISBN10(s string) bool {
	var n int
	var sum int
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' {
			continue
		}
		if n == 9 && c == 'X' {
			sum += 10 * (10 - n)
			n++
			continue
		}
		if !ascii.IsDigit(c) {
			return false
		}
		sum += int(c-'0') * (10 - n)
		n++
	}
	return n == 10 && sum%11 == 0
}

// ISBN13 checks if the string is a valid ISBN-13.
// It strips hyphens before validation.
func ISBN13(s string) bool {
	var n int
	var sum int
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' {
			continue
		}
		if !ascii.IsDigit(c) {
			return false
		}
		v := int(c - '0')
		if n%2 == 0 {
			sum += v
		} else {
			sum += v * 3
		}
		n++
	}
	return n == 13 && sum%10 == 0
}

// ISBN checks if the string is a valid ISBN (10 or 13).
func ISBN(s string) bool {
	return ISBN10(s) || ISBN13(s)
}

// Country2 checks if the string is a valid ISO 3166-1 alpha-2
// country code (e.g., "US").
func Country2(s string) bool {
	return len(s) == 2 && ascii.All(s, ascii.IsUpper)
}

// Country3 checks if the string is a valid ISO 3166-1 alpha-3
// country code (e.g., "USA").
func Country3(s string) bool {
	return len(s) == 3 && ascii.All(s, ascii.IsUpper)
}

// CountryN checks if the string is a valid ISO 3166-1 numeric
// country code (e.g., "840").
func CountryN(s string) bool {
	return len(s) == 3 && ascii.All(s, ascii.IsDigit)
}

// Currency checks if the string is a valid ISO 4217 currency code (e.g.,
// "EUR", "USD").
func Currency(s string) bool {
	return len(s) == 3 && ascii.All(s, ascii.IsUpper)
}

// UUID checks if the string is a valid Version 4 or 7 UUID as defined in RFC
// 4122 and RFC 9562.
func UUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// Lat checks if the number is a valid latitude coordinate (-90 to 90).
func Lat(f float32) bool {
	return f >= -90 && f <= 90
}

// Lon checks if the number is a valid longitude coordinate (-180 to 180).
func Lon(f float32) bool {
	return f >= -180 && f <= 180
}

// MD5 checks if the string is a valid MD5 hash (32 hex characters).
func MD5(s string) bool {
	return isHash(s, 32)
}

// SHA256 checks if the string is a valid SHA256 hash (64 hex characters).
func SHA256(s string) bool {
	return isHash(s, 64)
}

// SHA384 checks if the string is a valid SHA384 hash (96 hex characters).
func SHA384(s string) bool {
	return isHash(s, 96)
}

// SHA512 checks if the string is a valid SHA512 hash (128 hex characters).
func SHA512(s string) bool {
	return isHash(s, 128)
}

// SemVer checks if the string is a valid Semantic Versioning 2.0.0 string.
// Note that the "v" prefix is mandatory.
func SemVer(s string) bool {
	return semver.IsValid(s)
}

// Phone checks if the string is a valid E.164 formatted phone number.
// The string must start with a '+' and be followed by 2 to 15 digits.
func Phone(s string) bool {
	if len(s) < 3 || len(s) > 16 || s[0] != '+' || s[1] < '1' || s[1] > '9' {
		return false
	}
	for i := 2; i < len(s); i++ {
		if !ascii.IsDigit(s[i]) {
			return false
		}
	}
	return true
}

// BIC checks if the string is a valid Business Identifier Code (ISO 9362).
func BIC(s string) bool {
	return rxBIC.MatchString(s)
}

// IBAN checks if the string is a valid International Bank Account Number.
// It ignores spaces and performs the modulo 97 check.
func IBAN(s string) bool {
	var b [34]byte
	var n int
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' {
			continue
		}
		if n >= 34 || !ascii.IsAlphaNum(c) {
			return false
		}
		b[n] = c
		n++
	}

	if n < 15 {
		return false
	}

	if !ascii.IsAlpha(b[0]) ||
		!ascii.IsAlpha(b[1]) ||
		!ascii.IsDigit(b[2]) ||
		!ascii.IsDigit(b[3]) {
		return false
	}

	var rem int
	// Modulo 97 check: move first 4 characters to the end.
	for i := 4; i < n; i++ {
		rem = mod97(rem, b[i])
	}
	for i := range 4 {
		rem = mod97(rem, b[i])
	}

	return rem == 1
}

// isHash reports whether the string has the specified length and consists
// entirely of hexadecimal characters.
func isHash(s string, n int) bool {
	return len(s) == n && ascii.All(s, ascii.IsHex)
}

// mod97 updates the running remainder for a large numeric string using the
// modulo 97 operation. If c is a letter, it is treated as a two-digit number
// (A=10, ..., Z=35) per the ISO 13616 standard for IBANs.
func mod97(rem int, c byte) int {
	var n, k int
	if ascii.IsDigit(c) {
		n = rem * 10
		k = int(c - '0')
	} else {
		n = rem * 100
		k = int(ascii.Upper(c) - 'A' + 10)
	}
	return (n + k) % 97
}
