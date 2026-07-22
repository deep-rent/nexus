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
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/dat/valid"
)

type mockItem struct {
	val string
}

func (i *mockItem) Validate(v *valid.Validator) {
	if i == nil {
		return
	}
	v.NotEmpty("val", i.val)
}

var _ valid.Validatable = (*mockItem)(nil)

// mockDeepItem simulates a struct that might be nested behind multiple
// interface or pointer boundaries in a slice.
type mockDeepItem struct {
	val string
}

func (m *mockDeepItem) Validate(v *valid.Validator) {
	if m == nil {
		return
	}
	v.NotEmpty("val", m.val)
}

var _ valid.Validatable = (*mockDeepItem)(nil)

type mockParent struct {
	child *mockItem
	items []mockItem
}

func (p *mockParent) Validate(v *valid.Validator) {
	if p == nil {
		return
	}
	v.Test("child", p.child)
	v.Each("items", p.items)
}

var _ valid.Validatable = (*mockParent)(nil)

func TestErrors_Size(t *testing.T) {
	t.Parallel()

	var errors valid.Error

	errors = valid.Error{}
	if exp, act := 0, errors.Size(); exp != act {
		t.Errorf("got size %d; want %d", act, exp)
	}

	errors = valid.Error{"a": {"1"}}
	if exp, act := 1, errors.Size(); exp != act {
		t.Errorf("got size %d; want %d", act, exp)
	}

	errors = valid.Error{"a": {"1", "2"}, "b": {"3", "4"}}
	if exp, act := 4, errors.Size(); exp != act {
		t.Errorf("got size %d; want %d", act, exp)
	}
}

func TestErrors_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give valid.Error
		want string
	}{
		{
			name: "single field single error",
			give: valid.Error{"name": {"must not be empty"}},
			want: "validation failed: name: must not be empty",
		},
		{
			name: "single field multiple errors",
			give: valid.Error{
				"age": {"must be at least 18", "must be an integer"},
			},
			want: "validation failed: age: must be at least 18, " +
				"must be an integer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.give.Error(); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}

	t.Run("multiple fields", func(t *testing.T) {
		t.Parallel()
		errs := valid.Error{"a": {"1"}, "b": {"2"}}
		got := errs.Error()
		if !strings.HasPrefix(got, "validation failed: ") ||
			!strings.Contains(got, "a: 1") ||
			!strings.Contains(got, "b: 2") {
			t.Errorf("bad map formatting: %s", got)
		}
	})
}

func TestValidator_Error(t *testing.T) {
	t.Parallel()

	v := valid.New()
	if err := v.Error(); err != nil {
		t.Errorf("before failing: should not have returned an error: %v", err)
	}

	v.Fail("f", "msg")
	if err := v.Error(); err == nil {
		t.Error("after failing: should have returned an error")
	}
}

func TestTest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give any
		want valid.Error
	}{
		{
			name: "valid target",
			give: &mockItem{val: "ok"},
			want: nil,
		},
		{
			name: "invalid target",
			give: &mockItem{val: ""},
			want: valid.Error{"val": {"must not be empty"}},
		},
		{
			name: "nested valid target",
			give: &mockParent{child: &mockItem{val: "ok"}},
			want: nil,
		},
		{
			name: "nested invalid target",
			give: &mockParent{child: &mockItem{val: ""}},
			want: valid.Error{"child.val": {"must not be empty"}},
		},
		{
			name: "nested nil target",
			give: &mockParent{child: nil},
			want: nil,
		},
		{
			name: "slice valid target",
			give: []mockItem{{val: "ok"}},
			want: nil,
		},
		{
			name: "slice invalid target",
			give: []mockItem{{val: ""}},
			want: valid.Error{"[0].val": {"must not be empty"}},
		},
		{
			name: "unsupported type",
			give: "just a string",
			want: nil,
		},
		{
			name: "nil target",
			give: nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := valid.Test(tt.give)
			if tt.want == nil {
				if err != nil {
					t.Errorf("should not have returned an error: %v", err)
				}
				return
			}
			got, ok := errors.AsType[valid.Error](err)
			if !ok {
				t.Fatalf("got error of type %T; want valid.Error", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestEach(t *testing.T) {
	t.Parallel()

	var deepPtr *mockItem
	var deepInterface any = &mockItem{val: ""}

	tests := []struct {
		name string
		give any
		want valid.Error
	}{
		{
			name: "valid slice of structs",
			give: []mockItem{{val: "a"}, {val: "b"}},
			want: nil,
		},
		{
			name: "invalid slice of structs",
			give: []mockItem{{val: "a"}, {val: ""}},
			want: valid.Error{"[1].val": {"must not be empty"}},
		},
		{
			name: "invalid slice of pointers",
			give: []*mockItem{{val: ""}},
			want: valid.Error{"[0].val": {"must not be empty"}},
		},
		{
			name: "slice of any with nested types",
			give: []any{nil, deepPtr, deepInterface},
			want: valid.Error{"[2].val": {"must not be empty"}},
		},
		{
			name: "non-slice input ignored",
			give: "not a slice",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := valid.Each(tt.give)
			if tt.want == nil {
				if err != nil {
					t.Errorf("should not have returned an error: %v", err)
				}
				return
			}
			got, ok := errors.AsType[valid.Error](err)
			if !ok {
				t.Fatalf("got error of type %T; want valid.Error", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestValidator_NestedPaths(t *testing.T) {
	t.Parallel()

	p := &mockParent{
		child: &mockItem{val: ""},
		items: []mockItem{{val: "ok"}, {val: ""}},
	}

	err := valid.Test(p)
	got, ok := errors.AsType[valid.Error](err)
	if !ok {
		t.Fatalf("got error of type %T; want valid.Error", err)
	}

	want := valid.Error{
		"child.val":    {"must not be empty"},
		"items[1].val": {"must not be empty"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestValidator_Methods(t *testing.T) {
	t.Parallel()

	var (
		now = time.Now()
		rx  = regexp.MustCompile(`^[0-9]+$`)
	)

	tests := []struct {
		name  string
		apply func(v *valid.Validator)
		field string
		want  string
	}{
		{
			name:  "Min",
			apply: func(v *valid.Validator) { v.Min("f", 1.0, 5.0) },
			field: "f",
			want:  "must be at least 5",
		},
		{
			name:  "Max",
			apply: func(v *valid.Validator) { v.Max("f", 10.0, 5.0) },
			field: "f",
			want:  "must be at most 5",
		},
		{
			name:  "MinInt",
			apply: func(v *valid.Validator) { v.MinInt("f", 1, 5) },
			field: "f",
			want:  "must be at least 5",
		},
		{
			name:  "MaxInt",
			apply: func(v *valid.Validator) { v.MaxInt("f", 10, 5) },
			field: "f",
			want:  "must be at most 5",
		},
		{
			name:  "MinInt64",
			apply: func(v *valid.Validator) { v.MinInt64("f", 1, 5) },
			field: "f",
			want:  "must be at least 5",
		},
		{
			name:  "MaxInt64",
			apply: func(v *valid.Validator) { v.MaxInt64("f", 10, 5) },
			field: "f",
			want:  "must be at most 5",
		},
		{
			name:  "MinUint",
			apply: func(v *valid.Validator) { v.MinUint("f", 1, 5) },
			field: "f",
			want:  "must be at least 5",
		},
		{
			name:  "MaxUint",
			apply: func(v *valid.Validator) { v.MaxUint("f", 10, 5) },
			field: "f",
			want:  "must be at most 5",
		},
		{
			name:  "MinUint64",
			apply: func(v *valid.Validator) { v.MinUint64("f", 1, 5) },
			field: "f",
			want:  "must be at least 5",
		},
		{
			name:  "MaxUint64",
			apply: func(v *valid.Validator) { v.MaxUint64("f", 10, 5) },
			field: "f",
			want:  "must be at most 5",
		},
		{
			name:  "Between",
			apply: func(v *valid.Validator) { v.Between("f", 10.0, 1.0, 5.0) },
			field: "f",
			want:  "must be between 1 and 5",
		},
		{
			name:  "BetweenInt",
			apply: func(v *valid.Validator) { v.BetweenInt("f", 10, 1, 5) },
			field: "f",
			want:  "must be between 1 and 5",
		},
		{
			name:  "BetweenInt64",
			apply: func(v *valid.Validator) { v.BetweenInt64("f", 10, 1, 5) },
			field: "f",
			want:  "must be between 1 and 5",
		},
		{
			name:  "BetweenUint",
			apply: func(v *valid.Validator) { v.BetweenUint("f", 10, 1, 5) },
			field: "f",
			want:  "must be between 1 and 5",
		},
		{
			name:  "BetweenUint64",
			apply: func(v *valid.Validator) { v.BetweenUint64("f", 10, 1, 5) },
			field: "f",
			want:  "must be between 1 and 5",
		},
		{
			name:  "MinLen",
			apply: func(v *valid.Validator) { v.MinLen("f", "a", 5) },
			field: "f",
			want:  "length must be at least 5",
		},
		{
			name:  "MaxLen",
			apply: func(v *valid.Validator) { v.MaxLen("f", "abcdef", 5) },
			field: "f",
			want:  "length must be at most 5",
		},
		{
			name:  "Len",
			apply: func(v *valid.Validator) { v.Len("f", "a", 5) },
			field: "f",
			want:  "length must be exactly 5",
		},
		{
			name:  "MinSize",
			apply: func(v *valid.Validator) { v.MinSize("f", 1, 5) },
			field: "f",
			want:  "size must be at least 5",
		},
		{
			name:  "MaxSize",
			apply: func(v *valid.Validator) { v.MaxSize("f", 10, 5) },
			field: "f",
			want:  "size must be at most 5",
		},
		{
			name:  "Size",
			apply: func(v *valid.Validator) { v.Size("f", 1, 5) },
			field: "f",
			want:  "size must be exactly 5",
		},
		{
			name:  "Unique",
			apply: func(v *valid.Validator) { v.Unique("f", []string{"a", "a"}) },
			field: "f",
			want:  "must contain unique items",
		},
		{
			name: "Whitelist",
			apply: func(v *valid.Validator) {
				v.Whitelist("f", "a", "b", "c")
			},
			field: "f",
			want:  "must be one of the allowed values",
		},
		{
			name: "Blacklist",
			apply: func(v *valid.Validator) {
				v.Blacklist("f", "a", "a", "b")
			},
			field: "f",
			want:  "must not be one of the denied values",
		},
		{
			name:  "NotEmpty",
			apply: func(v *valid.Validator) { v.NotEmpty("f", "") },
			field: "f",
			want:  "must not be empty",
		},
		{
			name:  "NotBlank",
			apply: func(v *valid.Validator) { v.NotBlank("f", "   ") },
			field: "f",
			want:  "must not be blank",
		},
		{
			name:  "Prefix",
			apply: func(v *valid.Validator) { v.Prefix("f", "abc", "z") },
			field: "f",
			want:  `must start with "z"`,
		},
		{
			name:  "Suffix",
			apply: func(v *valid.Validator) { v.Suffix("f", "abc", "z") },
			field: "f",
			want:  `must end with "z"`,
		},
		{
			name:  "Contains",
			apply: func(v *valid.Validator) { v.Contains("f", "abc", "z") },
			field: "f",
			want:  `must contain "z"`,
		},
		{
			name:  "Match",
			apply: func(v *valid.Validator) { v.Match("f", "abc", rx) },
			field: "f",
			want:  `must match the pattern ^[0-9]+$`,
		},
		{
			name: "Before",
			apply: func(v *valid.Validator) {
				v.Before("f", now, now.Add(-time.Hour))
			},
			field: "f",
			want: fmt.Sprintf("must be before %v",
				now.Add(-time.Hour).Format(time.RFC3339)),
		},
		{
			name: "After",
			apply: func(v *valid.Validator) {
				v.After("f", now.Add(-time.Hour), now)
			},
			field: "f",
			want: fmt.Sprintf("must be after %v",
				now.Format(time.RFC3339)),
		},
		{
			name:  "CIDR",
			apply: func(v *valid.Validator) { v.CIDR("f", "bad") },
			field: "f",
			want:  "must be a valid CIDR",
		},
		{
			name:  "CIDRv4",
			apply: func(v *valid.Validator) { v.CIDRv4("f", "bad") },
			field: "f",
			want:  "must be a valid IPv4 CIDR",
		},
		{
			name:  "CIDRv6",
			apply: func(v *valid.Validator) { v.CIDRv6("f", "bad") },
			field: "f",
			want:  "must be a valid IPv6 CIDR",
		},
		{
			name:  "Hostname",
			apply: func(v *valid.Validator) { v.Hostname("f", "bad!") },
			field: "f",
			want:  "must be a valid hostname",
		},
		{
			name:  "Port",
			apply: func(v *valid.Validator) { v.Port("f", 0) },
			field: "f",
			want:  "must be a valid port number",
		},
		{
			name:  "IP",
			apply: func(v *valid.Validator) { v.IP("f", "bad") },
			field: "f",
			want:  "must be a valid IP address",
		},
		{
			name:  "IPv4",
			apply: func(v *valid.Validator) { v.IPv4("f", "bad") },
			field: "f",
			want:  "must be a valid IPv4 address",
		},
		{
			name:  "IPv6",
			apply: func(v *valid.Validator) { v.IPv6("f", "bad") },
			field: "f",
			want:  "must be a valid IPv6 address",
		},
		{
			name:  "FQDN",
			apply: func(v *valid.Validator) { v.FQDN("f", "bad") },
			field: "f",
			want:  "must be a valid FQDN",
		},
		{
			name:  "URI",
			apply: func(v *valid.Validator) { v.URI("f", "bad") },
			field: "f",
			want:  "must be a valid URI",
		},
		{
			name:  "URL",
			apply: func(v *valid.Validator) { v.URL("f", "bad") },
			field: "f",
			want:  "must be a valid URL",
		},
		{
			name:  "URN",
			apply: func(v *valid.Validator) { v.URN("f", "bad") },
			field: "f",
			want:  "must be a valid URN",
		},
		{
			name:  "Alpha",
			apply: func(v *valid.Validator) { v.Alpha("f", "123") },
			field: "f",
			want:  "must contain only alphabetical characters",
		},
		{
			name:  "AlphaNum",
			apply: func(v *valid.Validator) { v.AlphaNum("f", "!") },
			field: "f",
			want:  "must contain only alphanumeric characters",
		},
		{
			name:  "ASCII",
			apply: func(v *valid.Validator) { v.ASCII("f", "€") },
			field: "f",
			want:  "must contain only ASCII characters",
		},
		{
			name:  "Slug",
			apply: func(v *valid.Validator) { v.Slug("f", "bad_slug") },
			field: "f",
			want:  "must be a valid slug",
		},
		{
			name:  "Upper",
			apply: func(v *valid.Validator) { v.Upper("f", "abc") },
			field: "f",
			want:  "must contain only uppercase characters",
		},
		{
			name:  "Lower",
			apply: func(v *valid.Validator) { v.Lower("f", "ABC") },
			field: "f",
			want:  "must contain only lowercase characters",
		},
		{
			name:  "Base64",
			apply: func(v *valid.Validator) { v.Base64("f", "!") },
			field: "f",
			want:  "must be a valid Base64 string",
		},
		{
			name:  "Base64URL",
			apply: func(v *valid.Validator) { v.Base64URL("f", "!") },
			field: "f",
			want:  "must be a valid Base64URL string",
		},
		{
			name:  "MAC",
			apply: func(v *valid.Validator) { v.MAC("f", "bad") },
			field: "f",
			want:  "must be a valid MAC address",
		},
		{
			name:  "Lang",
			apply: func(v *valid.Validator) { v.Lang("f", "___") },
			field: "f",
			want:  "must be a valid BCP 47 language tag",
		},
		{
			name:  "JSON",
			apply: func(v *valid.Validator) { v.JSON("f", "bad") },
			field: "f",
			want:  "must be a valid JSON document",
		},
		{
			name:  "MIME",
			apply: func(v *valid.Validator) { v.MIME("f", "bad") },
			field: "f",
			want:  "must be a valid MIME type",
		},
		{
			name:  "CreditCard",
			apply: func(v *valid.Validator) { v.CreditCard("f", "bad") },
			field: "f",
			want:  "must be a valid credit card number",
		},
		{
			name:  "Email",
			apply: func(v *valid.Validator) { v.Email("f", "bad") },
			field: "f",
			want:  "must be a valid email address",
		},
		{
			name:  "Hex",
			apply: func(v *valid.Validator) { v.Hex("f", "xyz") },
			field: "f",
			want:  "must be a valid hexadecimal number",
		},
		{
			name:  "HexColor",
			apply: func(v *valid.Validator) { v.HexColor("f", "xyz") },
			field: "f",
			want:  "must be a valid hex color code",
		},
		{
			name:  "ISSN",
			apply: func(v *valid.Validator) { v.ISSN("f", "bad") },
			field: "f",
			want:  "must be a valid ISSN",
		},
		{
			name:  "ISBN10",
			apply: func(v *valid.Validator) { v.ISBN10("f", "bad") },
			field: "f",
			want:  "must be a valid ISBN-10",
		},
		{
			name:  "ISBN13",
			apply: func(v *valid.Validator) { v.ISBN13("f", "bad") },
			field: "f",
			want:  "must be a valid ISBN-13",
		},
		{
			name:  "ISBN",
			apply: func(v *valid.Validator) { v.ISBN("f", "bad") },
			field: "f",
			want:  "must be a valid ISBN",
		},
		{
			name:  "Country2",
			apply: func(v *valid.Validator) { v.Country2("f", "bad") },
			field: "f",
			want:  "must be a valid ISO 3166-1 alpha-2 code",
		},
		{
			name:  "Country3",
			apply: func(v *valid.Validator) { v.Country3("f", "bad") },
			field: "f",
			want:  "must be a valid ISO 3166-1 alpha-3 code",
		},
		{
			name:  "CountryN",
			apply: func(v *valid.Validator) { v.CountryN("f", "bad") },
			field: "f",
			want:  "must be a valid ISO 3166-1 numeric code",
		},
		{
			name:  "Currency",
			apply: func(v *valid.Validator) { v.Currency("f", "bad") },
			field: "f",
			want:  "must be a valid ISO 4217 currency code",
		},
		{
			name:  "UUID",
			apply: func(v *valid.Validator) { v.UUID("f", "bad") },
			field: "f",
			want:  "must be a valid UUID",
		},
		{
			name:  "Lat",
			apply: func(v *valid.Validator) { v.Lat("f", 100) },
			field: "f",
			want:  "must be a valid latitude",
		},
		{
			name:  "Lon",
			apply: func(v *valid.Validator) { v.Lon("f", 200) },
			field: "f",
			want:  "must be a valid longitude",
		},
		{
			name:  "MD5",
			apply: func(v *valid.Validator) { v.MD5("f", "bad") },
			field: "f",
			want:  "must be a valid MD5 hash",
		},
		{
			name:  "SHA256",
			apply: func(v *valid.Validator) { v.SHA256("f", "bad") },
			field: "f",
			want:  "must be a valid SHA256 hash",
		},
		{
			name:  "SHA384",
			apply: func(v *valid.Validator) { v.SHA384("f", "bad") },
			field: "f",
			want:  "must be a valid SHA384 hash",
		},
		{
			name:  "SHA512",
			apply: func(v *valid.Validator) { v.SHA512("f", "bad") },
			field: "f",
			want:  "must be a valid SHA512 hash",
		},
		{
			name:  "SemVer",
			apply: func(v *valid.Validator) { v.SemVer("f", "bad") },
			field: "f",
			want:  "must be a valid semantic version",
		},
		{
			name:  "Phone",
			apply: func(v *valid.Validator) { v.Phone("f", "bad") },
			field: "f",
			want:  "must be a valid E.164 phone number",
		},
		{
			name:  "BIC",
			apply: func(v *valid.Validator) { v.BIC("f", "bad") },
			field: "f",
			want:  "must be a valid BIC",
		},
		{
			name:  "IBAN",
			apply: func(v *valid.Validator) { v.IBAN("f", "bad") },
			field: "f",
			want:  "must be a valid IBAN",
		},
		{
			name: "EscapedPath",
			apply: func(v *valid.Validator) {
				v.Email("a.b", "bad")
			},
			field: `a\.b`,
			want:  "must be a valid email address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := valid.New()
			tt.apply(v)

			err := v.Error()
			if err == nil {
				t.Fatal("should have returned a validation error")
			}

			gotErr, ok := errors.AsType[valid.Error](err)
			if !ok {
				t.Fatalf("got error of type %T; want valid.Error", err)
			}

			msgs, ok := gotErr[tt.field]
			if !ok {
				t.Fatalf("no errors for field %q in %v", tt.field, gotErr)
			}

			if len(msgs) != 1 || msgs[0] != tt.want {
				t.Errorf("got %v; want [%q]", msgs, tt.want)
			}
		})
	}
}

func TestValidator_Unique_Short(t *testing.T) {
	t.Parallel()

	v := valid.New()
	v.Unique("f", []string{"a"}) // Under minimum length for a collision
	if err := v.Error(); err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}
}

func TestEach_EdgeCases(t *testing.T) {
	t.Parallel()

	item := &mockDeepItem{val: ""}
	ptrToItem := &item
	deepPtr := &ptrToItem

	tests := []struct {
		name string
		give any
		want valid.Error
	}{
		{
			name: "deeply nested pointer",
			give: []***mockDeepItem{deepPtr},
			want: valid.Error{"[0].val": {"must not be empty"}},
		},
		{
			name: "non-slice input",
			give: "not a slice at all",
			want: nil,
		},
		{
			name: "nil interface in slice",
			give: []any{nil, nil},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := valid.Each(tt.give)
			if tt.want == nil {
				if err != nil {
					t.Errorf("should not have returned an error: %v", err)
				}
				return
			}

			got, ok := errors.AsType[valid.Error](err)
			if !ok {
				t.Fatalf("got error of type %T; want valid.Error", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestValidator_PathEscaping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		field string
		want  string
	}{
		{
			name:  "standard field",
			field: "name",
			want:  "name",
		},
		{
			name:  "field with literal dots",
			field: "user.first.name",
			want:  `user\.first\.name`,
		},
		{
			name:  "empty field at root",
			field: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := valid.New()
			v.Fail(tt.field, "error")

			err := v.Error()
			gotErr, ok := errors.AsType[valid.Error](err)
			if !ok {
				t.Fatalf("got error of type %T; want valid.Error", err)
			}

			if _, exists := gotErr[tt.want]; !exists {
				t.Errorf("no errors for path %q in %v", tt.want, gotErr)
			}
		})
	}
}

func TestValidator_ShortCircuits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		apply func(v *valid.Validator)
	}{
		{
			name:  "Unique skip under 2 items",
			apply: func(v *valid.Validator) { v.Unique("f", []string{"a"}) },
		},
		{
			name:  "Test skip nil target",
			apply: func(v *valid.Validator) { v.Test("f", nil) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := valid.New()
			tt.apply(v)

			if err := v.Error(); err != nil {
				t.Errorf("should not have returned an error: %v", err)
			}
		})
	}
}
