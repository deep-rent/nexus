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

// Package valid provides utility functions for validating common formats and data types.
package valid

import (
	"net/netip"
	"net/url"
	"regexp"
	"strconv"

	"github.com/deep-rent/nexus/internal/ascii"
)

var (
	rxBase64   = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)
	rxURN      = regexp.MustCompile(`^(?i)urn:[a-z0-9][a-z0-9-]{0,31}:[a-z0-9()+,\-.:=@;$_!*'%/?#]+$`)
	rxHostname = regexp.MustCompile(`^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$`)
	rxFQDN     = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\.?$`)
	rxEmail    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	rxSemVer   = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-zA-Z0-9-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][a-zA-Z0-9-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)
	rxBIC      = regexp.MustCompile(`^[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?$`)
	rxLang     = regexp.MustCompile(`^[a-zA-Z]{2,8}(-[a-zA-Z0-9]{2,8})*$`)
)

// CIDR checks if the string is a valid Classless Inter-Domain Routing (CIDR)
// block.
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
// RFC 1123.
func Hostname(s string) bool {
	return len(s) != 0 && len(s) <= 253 && rxHostname.MatchString(s)
}

// Port checks if the string represents a valid network port number.
func Port(s string) bool {
	p, err := strconv.Atoi(s)
	return err == nil && p > 0 && p <= 65535
}

// IP checks if the string is a valid IP address.
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

// FQDN checks if the string is a Fully Qualified Domain Name.
func FQDN(s string) bool {
	return len(s) != 0 && len(s) <= 253 && rxFQDN.MatchString(s)
}

// URI checks if the string is a valid URI.
func URI(s string) bool {
	_, err := url.ParseRequestURI(s)
	return err == nil
}

// URL checks if the string is a valid URL with a scheme and host.
func URL(s string) bool {
	u, err := url.ParseRequestURI(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// URN checks if the string is a valid URN according to RFC 2141.
func URN(s string) bool {
	return rxURN.MatchString(s)
}

// Alpha checks if the string contains only alphabetical characters.
func Alpha(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !ascii.IsAlpha(rune(s[i])) {
			return false
		}
	}
	return true
}

// AlphaNum checks if the string contains only alphanumeric characters.
func AlphaNum(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !ascii.IsAlphaNum(rune(s[i])) {
			return false
		}
	}
	return true
}

// ASCII checks if the string contains only ASCII characters.
func ASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] > '\x7F' {
			return false
		}
	}
	return true
}

// Slug checks if the string is a valid URL slug.
func Slug(s string) bool {
	if s == "" || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ascii.IsLower(rune(c)) || ascii.IsDigit(rune(c)) {
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

// Upper checks if the string contains only uppercase characters.
func Upper(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !ascii.IsUpper(rune(s[i])) {
			return false
		}
	}
	return true
}

// Lower checks if the string contains only lowercase characters.
func Lower(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !ascii.IsLower(rune(s[i])) {
			return false
		}
	}
	return true
}

// Base64 checks if the string is a valid Base64 encoded string.
func Base64(s string) bool {
	return rxBase64.MatchString(s)
}

// Lang checks if the string is a valid BCP 47 language tag.
func Lang(s string) bool {
	return rxLang.MatchString(s)
}

// CreditCard checks if the string is a valid credit card number using the Luhn
// algorithm.
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

// Email checks if the string is a valid email address.
func Email(s string) bool {
	return rxEmail.MatchString(s)
}

// Hex checks if the string is a valid hexadecimal number.
func Hex(s string) bool {
	if len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !ascii.IsHex(rune(s[i])) {
			return false
		}
	}
	return true
}

// HexColor checks if the string is a valid hex color code.
func HexColor(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '#' {
		s = s[1:]
	}
	if len(s) != 3 && len(s) != 6 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !ascii.IsHex(rune(s[i])) {
			return false
		}
	}
	return true
}

// ISSN checks if the string is a valid International Standard Serial Number.
func ISSN(s string) bool {
	if len(s) != 9 {
		return false
	}
	return ascii.IsDigit(rune(s[0])) &&
		ascii.IsDigit(rune(s[1])) &&
		ascii.IsDigit(rune(s[2])) &&
		ascii.IsDigit(rune(s[3])) &&
		s[4] == '-' &&
		ascii.IsDigit(rune(s[5])) &&
		ascii.IsDigit(rune(s[6])) &&
		ascii.IsDigit(rune(s[7])) &&
		(ascii.IsDigit(rune(s[8])) || s[8] == 'X')
}

// ISBN10 checks if the string is a valid ISBN-10.
func ISBN10(s string) bool {
	var n int
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' {
			continue
		}
		if n == 9 && c == 'X' {
			n++
			continue
		}
		if !ascii.IsDigit(rune(c)) {
			return false
		}
		n++
	}
	return n == 10
}

// ISBN13 checks if the string is a valid ISBN-13.
func ISBN13(s string) bool {
	var n int
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' {
			continue
		}
		if !ascii.IsDigit(rune(c)) {
			return false
		}
		n++
	}
	return n == 13
}

// ISBN checks if the string is a valid ISBN (10 or 13).
func ISBN(s string) bool {
	return ISBN10(s) || ISBN13(s)
}

// CountryAlpha2 checks if the string is a valid ISO 3166-1 alpha-2
// country code.
func CountryAlpha2(s string) bool {
	return len(s) == 2 && ascii.IsUpper(rune(s[0])) &&
		ascii.IsUpper(rune(s[1]))
}

// CountryAlpha3 checks if the string is a valid ISO 3166-1 alpha-3
// country code.
func CountryAlpha3(s string) bool {
	return len(s) == 3 && ascii.IsUpper(rune(s[0])) &&
		ascii.IsUpper(rune(s[1])) &&
		ascii.IsUpper(rune(s[2]))
}

// Country checks if the string is a valid ISO 3166-1 numeric
// country code.
func Country(s string) bool {
	return len(s) == 3 && ascii.IsDigit(rune(s[0])) &&
		ascii.IsDigit(rune(s[1])) && ascii.IsDigit(rune(s[2]))
}

// Currency checks if the string is a valid ISO 4217 currency code.
func Currency(s string) bool {
	return len(s) == 3 && ascii.IsUpper(rune(s[0])) &&
		ascii.IsUpper(rune(s[1])) &&
		ascii.IsUpper(rune(s[2]))
}

// Lat checks if the number is a valid latitude coordinate (-90 to 90).
func Lat(f float32) bool {
	return f >= -90 && f <= 90
}

// Lon checks if the number is a valid longitude coordinate (-180 to 180).
func Lon(f float32) bool {
	return f >= -180 && f <= 180
}

// MD5 checks if the string is a valid MD5 hash.
func MD5(s string) bool {
	return isHash(s, 32)
}

// SHA256 checks if the string is a valid SHA256 hash.
func SHA256(s string) bool {
	return isHash(s, 64)
}

// SHA384 checks if the string is a valid SHA384 hash.
func SHA384(s string) bool {
	return isHash(s, 96)
}

// SHA512 checks if the string is a valid SHA512 hash.
func SHA512(s string) bool {
	return isHash(s, 128)
}

// SemVer checks if the string is a valid Semantic Versioning 2.0.0 string.
func SemVer(s string) bool {
	return rxSemVer.MatchString(s)
}

// Phone checks if the string is a valid E.164 formatted phone number.
func Phone(s string) bool {
	if len(s) < 3 || len(s) > 16 || s[0] != '+' || s[1] < '1' || s[1] > '9' {
		return false
	}
	for i := 2; i < len(s); i++ {
		if !ascii.IsDigit(rune(s[i])) {
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
func IBAN(s string) bool {
	var b [34]byte
	var n int
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' {
			continue
		}
		if n >= 34 || !ascii.IsAlphaNum(rune(c)) {
			return false
		}
		b[n] = c
		n++
	}

	if n < 15 {
		return false
	}

	if !ascii.IsAlpha(rune(b[0])) ||
		!ascii.IsAlpha(rune(b[1])) ||
		!ascii.IsDigit(rune(b[2])) ||
		!ascii.IsDigit(rune(b[3])) {
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

func isHash(s string, size int) bool {
	if len(s) != size {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !ascii.IsHex(rune(s[i])) {
			return false
		}
	}
	return true
}

func mod97(rem int, c byte) int {
	if ascii.IsDigit(rune(c)) {
		return (rem*10 + int(c-'0')) % 97
	}
	k := int(ascii.ToUpper(rune(c)) - 'A' + 10)
	return (100*rem + k) % 97
}
