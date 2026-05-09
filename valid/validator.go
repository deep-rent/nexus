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

// Test evaluates a boolean condition and adds an error message to the field
// if it evaluates to false. It serves as the foundation for all typed checks.
func (v *Validator) Test(ok bool, field, msg string) {
	if !ok {
		v.Fail(field, msg)
	}
}

// Nested dives into a nested [Validatable] struct. It appends the field name
// to the current path, seamlessly propagating any validation errors using dot
// notation (e.g., "user.address" or "items[0].name").
func (v *Validator) Nested(field string, target Validatable) {
	if target == nil {
		return
	}
	sub := &Validator{
		errs: v.errs,
		path: v.join(field),
	}
	_ = target.Validate(sub)
}

// join constructs the dot-notation path, accounting for array indexing.
func (v *Validator) join(field string) string {
	if v.path == "" {
		return field
	}
	if strings.HasPrefix(field, "[") {
		return v.path + field
	}
	return v.path + "." + field
}

// ----------------------------------------------------------------------------
// Comparison-based Checks
// ----------------------------------------------------------------------------

// Min asserts that a numeric value is at least the given minimum.
func (v *Validator) Min(field string, val, min float64) {
	v.Test(val >= min, field, fmt.Sprintf("must be at least %v", min))
}

// Max asserts that a numeric value is at most the given maximum.
func (v *Validator) Max(field string, val, max float64) {
	v.Test(val <= max, field, fmt.Sprintf("must be at most %v", max))
}

// GTE is an alias for Min (Greater Than or Equal).
func (v *Validator) GTE(field string, val, min float64) {
	v.Min(field, val, min)
}

// LTE is an alias for Max (Less Than or Equal).
func (v *Validator) LTE(field string, val, max float64) {
	v.Max(field, val, max)
}

// MinLen asserts that the length of a string or slice is at least min.
func (v *Validator) MinLen(field string, length, min int) {
	v.Test(length >= min, field, fmt.Sprintf("length must be at least %d", min))
}

// MaxLen asserts that the length of a string or slice is at most max.
func (v *Validator) MaxLen(field string, length, max int) {
	v.Test(length <= max, field, fmt.Sprintf("length must be at most %d", max))
}

// Unique asserts that all elements in a slice are unique.
func (v *Validator) Unique(field string, slice any) {
	rv := reflect.ValueOf(slice)
	if rv.Kind() != reflect.Slice {
		return
	}
	seen := make(map[any]bool, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		val := rv.Index(i).Interface()
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

// ----------------------------------------------------------------------------
// Standard Format Checks
// ----------------------------------------------------------------------------

func (v *Validator) CIDR(field, val string) {
	v.Test(CIDR(val), field, "must be a valid CIDR")
}

func (v *Validator) CIDRv4(field, val string) {
	v.Test(CIDRv4(val), field, "must be a valid IPv4 CIDR")
}

func (v *Validator) CIDRv6(field, val string) {
	v.Test(CIDRv6(val), field, "must be a valid IPv6 CIDR")
}

func (v *Validator) Hostname(field, val string) {
	v.Test(Hostname(val), field, "must be a valid hostname")
}

func (v *Validator) Port(field string, val int) {
	v.Test(Port(val), field, "must be a valid port number")
}

func (v *Validator) IP(field, val string) {
	v.Test(IP(val), field, "must be a valid IP address")
}

func (v *Validator) IPv4(field, val string) {
	v.Test(IPv4(val), field, "must be a valid IPv4 address")
}

func (v *Validator) IPv6(field, val string) {
	v.Test(IPv6(val), field, "must be a valid IPv6 address")
}

func (v *Validator) FQDN(field, val string) {
	v.Test(FQDN(val), field, "must be a valid FQDN")
}

func (v *Validator) URI(field, val string) {
	v.Test(URI(val), field, "must be a valid URI")
}

func (v *Validator) URL(field, val string) {
	v.Test(URL(val), field, "must be a valid URL")
}

func (v *Validator) URN(field, val string) {
	v.Test(URN(val), field, "must be a valid URN")
}

func (v *Validator) Alpha(field, val string) {
	v.Test(Alpha(val), field, "must contain only alphabetical characters")
}

func (v *Validator) AlphaNum(field, val string) {
	v.Test(AlphaNum(val), field, "must contain only alphanumeric characters")
}

func (v *Validator) ASCII(field, val string) {
	v.Test(ASCII(val), field, "must contain only ASCII characters")
}

func (v *Validator) Slug(field, val string) {
	v.Test(Slug(val), field, "must be a valid slug")
}

func (v *Validator) Upper(field, val string) {
	v.Test(Upper(val), field, "must contain only uppercase characters")
}

func (v *Validator) Lower(field, val string) {
	v.Test(Lower(val), field, "must contain only lowercase characters")
}

func (v *Validator) Base64(field, val string) {
	v.Test(Base64(val), field, "must be a valid Base64 string")
}

func (v *Validator) Base64URL(field, val string) {
	v.Test(Base64URL(val), field, "must be a valid Base64URL string")
}

func (v *Validator) MAC(field, val string) {
	v.Test(MAC(val), field, "must be a valid MAC address")
}

func (v *Validator) Lang(field, val string) {
	v.Test(Lang(val), field, "must be a valid BCP 47 language tag")
}

func (v *Validator) JSON(field, val string) {
	v.Test(JSON(val), field, "must be a valid JSON document")
}

func (v *Validator) MIME(field, val string) {
	v.Test(MIME(val), field, "must be a valid MIME type")
}

func (v *Validator) CreditCard(field, val string) {
	v.Test(CreditCard(val), field, "must be a valid credit card number")
}

func (v *Validator) Email(field, val string) {
	v.Test(Email(val), field, "must be a valid email address")
}

func (v *Validator) Hex(field, val string) {
	v.Test(Hex(val), field, "must be a valid hexadecimal number")
}

func (v *Validator) HexColor(field, val string) {
	v.Test(HexColor(val), field, "must be a valid hex color code")
}

func (v *Validator) ISSN(field, val string) {
	v.Test(ISSN(val), field, "must be a valid ISSN")
}

func (v *Validator) ISBN10(field, val string) {
	v.Test(ISBN10(val), field, "must be a valid ISBN-10")
}

func (v *Validator) ISBN13(field, val string) {
	v.Test(ISBN13(val), field, "must be a valid ISBN-13")
}

func (v *Validator) ISBN(field, val string) {
	v.Test(ISBN(val), field, "must be a valid ISBN")
}

func (v *Validator) CountryAlpha2(field, val string) {
	v.Test(CountryAlpha2(val), field, "must be a valid ISO 3166-1 alpha-2 code")
}

func (v *Validator) CountryAlpha3(field, val string) {
	v.Test(CountryAlpha3(val), field, "must be a valid ISO 3166-1 alpha-3 code")
}

func (v *Validator) Country(field, val string) {
	v.Test(Country(val), field, "must be a valid ISO 3166-1 numeric code")
}

func (v *Validator) Currency(field, val string) {
	v.Test(Currency(val), field, "must be a valid ISO 4217 currency code")
}

func (v *Validator) Lat(field string, val float32) {
	v.Test(Lat(val), field, "must be a valid latitude")
}

func (v *Validator) Lon(field string, val float32) {
	v.Test(Lon(val), field, "must be a valid longitude")
}

func (v *Validator) MD5(field, val string) {
	v.Test(MD5(val), field, "must be a valid MD5 hash")
}

func (v *Validator) SHA256(field, val string) {
	v.Test(SHA256(val), field, "must be a valid SHA256 hash")
}

func (v *Validator) SHA384(field, val string) {
	v.Test(SHA384(val), field, "must be a valid SHA384 hash")
}

func (v *Validator) SHA512(field, val string) {
	v.Test(SHA512(val), field, "must be a valid SHA512 hash")
}

func (v *Validator) SemVer(field, val string) {
	v.Test(SemVer(val), field, "must be a valid Semantic Version")
}

func (v *Validator) Phone(field, val string) {
	v.Test(Phone(val), field, "must be a valid E.164 phone number")
}

func (v *Validator) BIC(field, val string) {
	v.Test(BIC(val), field, "must be a valid BIC")
}

func (v *Validator) IBAN(field, val string) {
	v.Test(IBAN(val), field, "must be a valid IBAN")
}
