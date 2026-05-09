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
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
)

// Errors represents a collection of validation errors mapped by their
// corresponding field paths in dot notation. It naturally serializes to JSON,
// making it ideal for API error responses.
type Errors map[string][]string

// Error implements the error interface, providing a consolidated string
// representation of all validation failures.
func (e Errors) Error() string {
	var sb strings.Builder
	sb.WriteString("validation failed: ")
	first := true
	for path, msgs := range e {
		if !first {
			sb.WriteString("; ")
		}
		sb.WriteString(path)
		sb.WriteString(": ")
		sb.WriteString(strings.Join(msgs, ", "))
		first = false
	}
	return sb.String()
}

// Validatable describes a structure that can self-validate using a [Validator].
// It is typically implemented by API DTOs and request payloads.
type Validatable interface {
	Validate(v *Validator) error
}

// Validator orchestrates the validation of fields, builds dot-notation paths
// for nested structures, and aggregates error messages.
type Validator struct {
	errs Errors
	path string
}

// NewValidator creates and returns a new empty [Validator].
func NewValidator() *Validator {
	return &Validator{
		errs: make(Errors),
	}
}

// Error returns the composite validation error if any checks failed, or nil
// if all checks passed.
func (v *Validator) Error() error {
	if len(v.errs) == 0 {
		return nil
	}
	return v.errs
}

// Fail records an explicit error message against the given field.
func (v *Validator) Fail(field, msg string) {
	if v.errs == nil {
		v.errs = make(Errors)
	}
	p := v.join(field)
	v.errs[p] = append(v.errs[p], msg)
}

// Walk dives into a nested [Validatable] struct. It appends the field name
// to the current path, seamlessly propagating any validation errors using dot
// notation (e.g., "user.address" or "items[0].name").
func (v *Validator) Walk(field string, target Validatable) {
	if target == nil {
		return
	}
	sub := &Validator{
		errs: v.errs,
		path: v.join(field),
	}
	_ = target.Validate(sub)
}

// Each iterates over a slice and validates each element that implements the
// [Validatable] interface. It automatically manages array indexing in the
// dot-notation path (e.g., "items[0]", "items[1]").
func (v *Validator) Each(field string, slice any) {
	rv := reflect.ValueOf(slice)
	if rv.Kind() != reflect.Slice {
		return
	}
	p := v.join(field)
	for i := 0; i < rv.Len(); i++ {
		val := rv.Index(i)
		var target Validatable

		if t, ok := val.Interface().(Validatable); ok {
			if (val.Kind() == reflect.Pointer ||
				val.Kind() == reflect.Interface) && val.IsNil() {
				continue
			}
			target = t
		} else if val.CanAddr() {
			if t, ok := val.Addr().Interface().(Validatable); ok {
				target = t
			}
		}

		if target != nil {
			sub := &Validator{
				errs: v.errs,
				path: fmt.Sprintf("%s[%d]", p, i),
			}
			_ = target.Validate(sub)
		}
	}
}

// join constructs the dot-notation path, accounting for array indexing.
func (v *Validator) join(field string) string {
	if v.path == "" {
		return field
	}
	if len(field) > 0 && field[0] == '[' {
		return v.path + field
	}
	return v.path + "." + field
}

// ----------------------------------------------------------------------------
// Comparison-based Checks
// ----------------------------------------------------------------------------

// Min asserts that a numeric value is at least the given minimum.
func (v *Validator) Min(field string, val, min float64) {
	if val < min {
		v.Fail(field, fmt.Sprintf("must be at least %v", min))
	}
}

// Max asserts that a numeric value is at most the given maximum.
func (v *Validator) Max(field string, val, max float64) {
	if val > max {
		v.Fail(field, fmt.Sprintf("must be at most %v", max))
	}
}

// MinInt asserts that an integer value is at least the given minimum.
func (v *Validator) MinInt(field string, val, min int) {
	if val < min {
		v.Fail(field, fmt.Sprintf("must be at least %d", min))
	}
}

// MaxInt asserts that an integer value is at most the given maximum.
func (v *Validator) MaxInt(field string, val, max int) {
	if val > max {
		v.Fail(field, fmt.Sprintf("must be at most %d", max))
	}
}

// Between asserts that a numeric value is between min and max inclusive.
func (v *Validator) Between(field string, val, min, max float64) {
	if val < min || val > max {
		v.Fail(field, fmt.Sprintf("must be between %v and %v", min, max))
	}
}

// BetweenInt asserts that an integer value is between min and max inclusive.
func (v *Validator) BetweenInt(field string, val, min, max int) {
	if val < min || val > max {
		v.Fail(field, fmt.Sprintf("must be between %d and %d", min, max))
	}
}

// MinLen asserts that the length of a string is at least min.
func (v *Validator) MinLen(field, val string, min int) {
	if len(val) < min {
		v.Fail(field, fmt.Sprintf("length must be at least %d", min))
	}
}

// MaxLen asserts that the length of a string is at most max.
func (v *Validator) MaxLen(field, val string, max int) {
	if len(val) > max {
		v.Fail(field, fmt.Sprintf("length must be at most %d", max))
	}
}

// MinSize asserts that the size of a slice or map is at least min.
func (v *Validator) MinSize(field string, size, min int) {
	if size < min {
		v.Fail(field, fmt.Sprintf("size must be at least %d", min))
	}
}

// MaxSize asserts that the size of a slice or map is at most max.
func (v *Validator) MaxSize(field string, size, max int) {
	if size > max {
		v.Fail(field, fmt.Sprintf("size must be at most %d", max))
	}
}

// Unique asserts that all elements in a string slice are unique.
func (v *Validator) Unique(field string, slice []string) {
	if len(slice) < 2 {
		return
	}
	seen := make(map[string]bool, len(slice))
	for _, val := range slice {
		if seen[val] {
			v.Fail(field, "must contain unique items")
			return
		}
		seen[val] = true
	}
}

// Whitelist asserts that a value exactly matches one of the allowed options.
// The underlying concrete types must match.
func (v *Validator) Whitelist(field string, val any, list ...any) {
	if !slices.Contains(list, val) {
		v.Fail(field, "must be one of the allowed values")
	}
}

// Blacklist asserts that a value does not match any of the denied options.
// The underlying concrete types must match.
func (v *Validator) Blacklist(field string, val any, list ...any) {
	if slices.Contains(list, val) {
		v.Fail(field, "must not be one of the denied values")
	}
}

// NotEmpty asserts that a string is not empty.
func (v *Validator) NotEmpty(field, val string) {
	if val == "" {
		v.Fail(field, "must not be empty")
	}
}

// Match asserts that a string matches a regular expression.
func (v *Validator) Match(field, val string, rx *regexp.Regexp) {
	if !rx.MatchString(val) {
		v.Fail(field, fmt.Sprintf("must match the pattern %s", rx.String()))
	}
}

// ----------------------------------------------------------------------------
// Standard Format Checks
// ----------------------------------------------------------------------------

func (v *Validator) CIDR(field, val string) {
	if !CIDR(val) {
		v.Fail(field, "must be a valid CIDR")
	}
}

func (v *Validator) CIDRv4(field, val string) {
	if !CIDRv4(val) {
		v.Fail(field, "must be a valid IPv4 CIDR")
	}
}

func (v *Validator) CIDRv6(field, val string) {
	if !CIDRv6(val) {
		v.Fail(field, "must be a valid IPv6 CIDR")
	}
}

func (v *Validator) Hostname(field, val string) {
	if !Hostname(val) {
		v.Fail(field, "must be a valid hostname")
	}
}

func (v *Validator) Port(field string, val int) {
	if !Port(val) {
		v.Fail(field, "must be a valid port number")
	}
}

func (v *Validator) IP(field, val string) {
	if !IP(val) {
		v.Fail(field, "must be a valid IP address")
	}
}

func (v *Validator) IPv4(field, val string) {
	if !IPv4(val) {
		v.Fail(field, "must be a valid IPv4 address")
	}
}

func (v *Validator) IPv6(field, val string) {
	if !IPv6(val) {
		v.Fail(field, "must be a valid IPv6 address")
	}
}

func (v *Validator) FQDN(field, val string) {
	if !FQDN(val) {
		v.Fail(field, "must be a valid FQDN")
	}
}

func (v *Validator) URI(field, val string) {
	if !URI(val) {
		v.Fail(field, "must be a valid URI")
	}
}

func (v *Validator) URL(field, val string) {
	if !URL(val) {
		v.Fail(field, "must be a valid URL")
	}
}

func (v *Validator) URN(field, val string) {
	if !URN(val) {
		v.Fail(field, "must be a valid URN")
	}
}

func (v *Validator) Alpha(field, val string) {
	if !Alpha(val) {
		v.Fail(field, "must contain only alphabetical characters")
	}
}

func (v *Validator) AlphaNum(field, val string) {
	if !AlphaNum(val) {
		v.Fail(field, "must contain only alphanumeric characters")
	}
}

func (v *Validator) ASCII(field, val string) {
	if !ASCII(val) {
		v.Fail(field, "must contain only ASCII characters")
	}
}

func (v *Validator) Slug(field, val string) {
	if !Slug(val) {
		v.Fail(field, "must be a valid slug")
	}
}

func (v *Validator) Upper(field, val string) {
	if !Upper(val) {
		v.Fail(field, "must contain only uppercase characters")
	}
}

func (v *Validator) Lower(field, val string) {
	if !Lower(val) {
		v.Fail(field, "must contain only lowercase characters")
	}
}

func (v *Validator) Base64(field, val string) {
	if !Base64(val) {
		v.Fail(field, "must be a valid Base64 string")
	}
}

func (v *Validator) Base64URL(field, val string) {
	if !Base64URL(val) {
		v.Fail(field, "must be a valid Base64URL string")
	}
}

func (v *Validator) MAC(field, val string) {
	if !MAC(val) {
		v.Fail(field, "must be a valid MAC address")
	}
}

func (v *Validator) Lang(field, val string) {
	if !Lang(val) {
		v.Fail(field, "must be a valid BCP 47 language tag")
	}
}

func (v *Validator) JSON(field, val string) {
	if !JSON(val) {
		v.Fail(field, "must be a valid JSON document")
	}
}

func (v *Validator) MIME(field, val string) {
	if !MIME(val) {
		v.Fail(field, "must be a valid MIME type")
	}
}

func (v *Validator) CreditCard(field, val string) {
	if !CreditCard(val) {
		v.Fail(field, "must be a valid credit card number")
	}
}

func (v *Validator) Email(field, val string) {
	if !Email(val) {
		v.Fail(field, "must be a valid email address")
	}
}

func (v *Validator) Hex(field, val string) {
	if !Hex(val) {
		v.Fail(field, "must be a valid hexadecimal number")
	}
}

func (v *Validator) HexColor(field, val string) {
	if !HexColor(val) {
		v.Fail(field, "must be a valid hex color code")
	}
}

func (v *Validator) ISSN(field, val string) {
	if !ISSN(val) {
		v.Fail(field, "must be a valid ISSN")
	}
}

func (v *Validator) ISBN10(field, val string) {
	if !ISBN10(val) {
		v.Fail(field, "must be a valid ISBN-10")
	}
}

func (v *Validator) ISBN13(field, val string) {
	if !ISBN13(val) {
		v.Fail(field, "must be a valid ISBN-13")
	}
}

func (v *Validator) ISBN(field, val string) {
	if !ISBN(val) {
		v.Fail(field, "must be a valid ISBN")
	}
}

func (v *Validator) Country2(field, val string) {
	if !Country2(val) {
		v.Fail(field, "must be a valid ISO 3166-1 alpha-2 code")
	}
}

func (v *Validator) Country3(field, val string) {
	if !Country3(val) {
		v.Fail(field, "must be a valid ISO 3166-1 alpha-3 code")
	}
}

func (v *Validator) CountryN(field, val string) {
	if !CountryN(val) {
		v.Fail(field, "must be a valid ISO 3166-1 numeric code")
	}
}

func (v *Validator) Currency(field, val string) {
	if !Currency(val) {
		v.Fail(field, "must be a valid ISO 4217 currency code")
	}
}

func (v *Validator) Lat(field string, val float32) {
	if !Lat(val) {
		v.Fail(field, "must be a valid latitude")
	}
}

func (v *Validator) Lon(field string, val float32) {
	if !Lon(val) {
		v.Fail(field, "must be a valid longitude")
	}
}

func (v *Validator) MD5(field, val string) {
	if !MD5(val) {
		v.Fail(field, "must be a valid MD5 hash")
	}
}

func (v *Validator) SHA256(field, val string) {
	if !SHA256(val) {
		v.Fail(field, "must be a valid SHA256 hash")
	}
}

func (v *Validator) SHA384(field, val string) {
	if !SHA384(val) {
		v.Fail(field, "must be a valid SHA384 hash")
	}
}

func (v *Validator) SHA512(field, val string) {
	if !SHA512(val) {
		v.Fail(field, "must be a valid SHA512 hash")
	}
}

func (v *Validator) SemVer(field, val string) {
	if !SemVer(val) {
		v.Fail(field, "must be a valid Semantic Version")
	}
}

func (v *Validator) Phone(field, val string) {
	if !Phone(val) {
		v.Fail(field, "must be a valid E.164 phone number")
	}
}

func (v *Validator) BIC(field, val string) {
	if !BIC(val) {
		v.Fail(field, "must be a valid BIC")
	}
}

func (v *Validator) IBAN(field, val string) {
	if !IBAN(val) {
		v.Fail(field, "must be a valid IBAN")
	}
}
