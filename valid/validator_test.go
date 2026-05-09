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
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/valid"
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

func TestErrors_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give valid.Errors
		want string
	}{
		{
			name: "single field single error",
			give: valid.Errors{"name": {"must not be empty"}},
			want: "validation failed: name: must not be empty",
		},
		{
			name: "single field multiple errors",
			give: valid.Errors{
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
				t.Errorf("Errors.Error() = %q; want %q", got, tt.want)
			}
		})
	}

	t.Run("multiple fields", func(t *testing.T) {
		t.Parallel()
		errs := valid.Errors{"a": {"1"}, "b": {"2"}}
		got := errs.Error()
		if !strings.HasPrefix(got, "validation failed: ") ||
			!strings.Contains(got, "a: 1") ||
			!strings.Contains(got, "b: 2") {
			t.Errorf("Unexpected map formatting: %s", got)
		}
	})
}

func TestValidator_Error(t *testing.T) {
	t.Parallel()

	v := valid.New()
	if err := v.Error(); err != nil {
		t.Errorf("New().Error() = %v; want nil", err)
	}

	v.Fail("f", "msg")
	if err := v.Error(); err == nil {
		t.Error("Error() = nil; want error")
	}
}

func TestTest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give valid.Validatable
		want valid.Errors
	}{
		{
			name: "valid target",
			give: &mockItem{val: "ok"},
			want: nil,
		},
		{
			name: "invalid target",
			give: &mockItem{val: ""},
			want: valid.Errors{"val": {"must not be empty"}},
		},
		{
			name: "nested valid target",
			give: &mockParent{child: &mockItem{val: "ok"}},
			want: nil,
		},
		{
			name: "nested invalid target",
			give: &mockParent{child: &mockItem{val: ""}},
			want: valid.Errors{"child.val": {"must not be empty"}},
		},
		{
			name: "nested nil target",
			give: &mockParent{child: nil},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := valid.Test(tt.give)
			if tt.want == nil {
				if err != nil {
					t.Errorf("Test() = %v; want nil", err)
				}
				return
			}
			got, ok := err.(valid.Errors)
			if !ok {
				t.Fatalf("Test() returned %T; want valid.Errors", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Test() = %v; want %v", got, tt.want)
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
		want valid.Errors
	}{
		{
			name: "valid slice of structs",
			give: []mockItem{{val: "a"}, {val: "b"}},
			want: nil,
		},
		{
			name: "invalid slice of structs",
			give: []mockItem{{val: "a"}, {val: ""}},
			want: valid.Errors{"[1].val": {"must not be empty"}},
		},
		{
			name: "invalid slice of pointers",
			give: []*mockItem{{val: ""}},
			want: valid.Errors{"[0].val": {"must not be empty"}},
		},
		{
			name: "slice of any with nested types",
			give: []any{nil, deepPtr, deepInterface},
			want: valid.Errors{"[2].val": {"must not be empty"}},
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
					t.Errorf("Each() = %v; want nil", err)
				}
				return
			}
			got, ok := err.(valid.Errors)
			if !ok {
				t.Fatalf("Each() returned %T; want valid.Errors", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Each() = %v; want %v", got, tt.want)
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
	got, ok := err.(valid.Errors)
	if !ok {
		t.Fatalf("Test() returned %T; want valid.Errors", err)
	}

	want := valid.Errors{
		"child.val":    {"must not be empty"},
		"items[1].val": {"must not be empty"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Test() = %v; want %v", got, want)
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
		{"Min", func(v *valid.Validator) { v.Min("f", 1.0, 5.0) }, "f", "must be at least 5"},
		{"Max", func(v *valid.Validator) { v.Max("f", 10.0, 5.0) }, "f", "must be at most 5"},
		{"MinInt", func(v *valid.Validator) { v.MinInt("f", 1, 5) }, "f", "must be at least 5"},
		{"MaxInt", func(v *valid.Validator) { v.MaxInt("f", 10, 5) }, "f", "must be at most 5"},
		{"Between", func(v *valid.Validator) { v.Between("f", 10.0, 1.0, 5.0) }, "f", "must be between 1 and 5"},
		{"BetweenInt", func(v *valid.Validator) { v.BetweenInt("f", 10, 1, 5) }, "f", "must be between 1 and 5"},
		{"MinLen", func(v *valid.Validator) { v.MinLen("f", "a", 5) }, "f", "length must be at least 5"},
		{"MaxLen", func(v *valid.Validator) { v.MaxLen("f", "abcdef", 5) }, "f", "length must be at most 5"},
		{"Len", func(v *valid.Validator) { v.Len("f", "a", 5) }, "f", "length must be exactly 5"},
		{"MinSize", func(v *valid.Validator) { v.MinSize("f", 1, 5) }, "f", "size must be at least 5"},
		{"MaxSize", func(v *valid.Validator) { v.MaxSize("f", 10, 5) }, "f", "size must be at most 5"},
		{"Size", func(v *valid.Validator) { v.Size("f", 1, 5) }, "f", "size must be exactly 5"},
		{"Unique", func(v *valid.Validator) { v.Unique("f", []string{"a", "a"}) }, "f", "must contain unique items"},
		{"Whitelist", func(v *valid.Validator) { v.Whitelist("f", "a", "b", "c") }, "f", "must be one of the allowed values"},
		{"Blacklist", func(v *valid.Validator) { v.Blacklist("f", "a", "a", "b") }, "f", "must not be one of the denied values"},
		{"NotEmpty", func(v *valid.Validator) { v.NotEmpty("f", "") }, "f", "must not be empty"},
		{"NotBlank", func(v *valid.Validator) { v.NotBlank("f", "   ") }, "f", "must not be blank"},
		{"Prefix", func(v *valid.Validator) { v.Prefix("f", "abc", "z") }, "f", `must start with "z"`},
		{"Suffix", func(v *valid.Validator) { v.Suffix("f", "abc", "z") }, "f", `must end with "z"`},
		{"Contains", func(v *valid.Validator) { v.Contains("f", "abc", "z") }, "f", `must contain "z"`},
		{"Match", func(v *valid.Validator) { v.Match("f", "abc", rx) }, "f", `must match the pattern ^[0-9]+$`},
		{"Before", func(v *valid.Validator) { v.Before("f", now, now.Add(-time.Hour)) }, "f", fmt.Sprintf("must be before %v", now.Add(-time.Hour).Format(time.RFC3339))},
		{"After", func(v *valid.Validator) { v.After("f", now.Add(-time.Hour), now) }, "f", fmt.Sprintf("must be after %v", now.Format(time.RFC3339))},
		{"CIDR", func(v *valid.Validator) { v.CIDR("f", "bad") }, "f", "must be a valid CIDR"},
		{"Email", func(v *valid.Validator) { v.Email("f", "bad") }, "f", "must be a valid email address"},
		{"EscapedPath", func(v *valid.Validator) { v.Email("a.b", "bad") }, `a\.b`, "must be a valid email address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := valid.New()
			tt.apply(v)

			err := v.Error()
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}

			gotErrs, ok := err.(valid.Errors)
			if !ok {
				t.Fatalf("expected valid.Errors, got %T", err)
			}

			msgs, ok := gotErrs[tt.field]
			if !ok {
				t.Fatalf("missing expected field %q in %v", tt.field, gotErrs)
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
		t.Errorf("Unique() returned %v; want nil", err)
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
		want valid.Errors
	}{
		{
			name: "deeply nested pointer",
			give: []***mockDeepItem{deepPtr},
			want: valid.Errors{"[0].val": {"must not be empty"}},
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
					t.Errorf("Each() = %v; want nil", err)
				}
				return
			}

			got, ok := err.(valid.Errors)
			if !ok {
				t.Fatalf("Each() returned %T; want valid.Errors", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Each() = %v; want %v", got, tt.want)
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

			gotErrs, ok := v.Error().(valid.Errors)
			if !ok {
				t.Fatalf("Error() returned %T; want valid.Errors", v.Error())
			}

			if _, exists := gotErrs[tt.want]; !exists {
				t.Errorf("expected path %q to exist in %v", tt.want, gotErrs)
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
				t.Errorf("expected nil error, got %v", err)
			}
		})
	}
}
