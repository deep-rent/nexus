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

package bind_test

import (
	"encoding"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/internal/bind"
	"github.com/deep-rent/nexus/internal/snake"
)

type mockSource map[string][]string

func (m mockSource) Lookup(key string) ([]string, bool) {
	v, ok := m[key]
	return v, ok
}

var _ bind.Source = (*mockSource)(nil)

func TestBinder_Bind(t *testing.T) {
	t.Parallel()

	type Config struct {
		Host    string   `bind:"host"`
		Port    int      `bind:"port,default:8080"`
		Tags    []string `bind:"tags,split:','"`
		Missing string   `bind:"missing,required"`
	}

	b := bind.New("bind")

	t.Run("success", func(t *testing.T) {
		var cfg Config
		src := mockSource{
			"host":    {"localhost"},
			"tags":    {"a,b"},
			"missing": {"foo"},
		}

		err := b.Bind(&cfg, "", src)
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}

		if cfg.Host != "localhost" {
			t.Errorf("host: got %q; want 'localhost'", cfg.Host)
		}
		if cfg.Port != 8080 {
			t.Errorf("port: got %d; want 8080", cfg.Port)
		}
		if !reflect.DeepEqual(cfg.Tags, []string{"a", "b"}) {
			t.Errorf("tags: got %v; want [a b]", cfg.Tags)
		}
	})

	t.Run("missing required", func(t *testing.T) {
		var cfg Config
		src := mockSource{
			"host": {"localhost"},
		}

		err := b.Bind(&cfg, "", src)
		if err == nil {
			t.Fatal("should have returned an error")
		}
	})

	t.Run("multiple values", func(t *testing.T) {
		type ArrayConfig struct {
			IDs []int `bind:"ids"`
		}
		var cfg ArrayConfig
		src := mockSource{
			"ids": {"1", "2", "3"},
		}

		err := b.Bind(&cfg, "", src)
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}

		if !reflect.DeepEqual(cfg.IDs, []int{1, 2, 3}) {
			t.Errorf("got %v; want [1 2 3]", cfg.IDs)
		}
	})
}

// A malformed tag is a configuration mistake in the caller's own source, but
// it is reported rather than raised: Bind returns an error, so a program that
// parses configuration can say what is wrong instead of dying.
func TestBinder_InvalidTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		bind func() error
		want string
	}{
		{
			name: "unknown option",
			bind: func() error {
				var cfg struct {
					Host string `bind:"host,unknownOption:true"`
				}
				return bind.New("bind").Bind(&cfg, "", mockSource{})
			},
			want: `unknown option: "unknownOption"`,
		},
		{
			name: "duplicate option",
			bind: func() error {
				var cfg struct {
					Host string `bind:"host,required,required"`
				}
				return bind.New("bind").Bind(&cfg, "", mockSource{})
			},
			want: `duplicate option: "required"`,
		},
		{
			name: "inline on a named field",
			bind: func() error {
				type Inner struct {
					Name string `bind:"name"`
				}
				var cfg struct {
					Inner Inner `bind:",inline"`
				}
				return bind.New("bind").Bind(&cfg, "", mockSource{})
			},
			want: `requires an embedded field`,
		},
		{
			name: "inline on a scalar",
			bind: func() error {
				var cfg struct {
					string `bind:",inline"`
				}
				return bind.New("bind").Bind(&cfg, "", mockSource{})
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("should not have panicked: %v", r)
				}
			}()

			err := tt.bind()
			if tt.want == "" {
				return
			}

			if err == nil {
				t.Fatal("should have returned an error")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("want match for %q; got %q", tt.want, err)
			}
		})
	}
}

// A source may report a key as present while carrying no values. There is
// nothing to assign, so the field is left to its default rather than causing
// an out-of-range panic.
func TestBinder_EmptyValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  mockSource
		want string
	}{
		{"no values", mockSource{"host": {}}, "fallback"},
		{"absent", mockSource{}, "fallback"},
		{"present", mockSource{"host": {"example.com"}}, "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("should not have panicked: %v", r)
				}
			}()

			var cfg struct {
				Host string `bind:"host,default:fallback"`
			}

			if err := bind.New("bind").Bind(&cfg, "", tt.src); err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}

			if cfg.Host != tt.want {
				t.Errorf("got %q; want %q", cfg.Host, tt.want)
			}
		})
	}
}

// A key present with no values must still satisfy nothing: a required field
// is reported as missing rather than bound to an empty string.
func TestBinder_EmptyValuesAreMissing(t *testing.T) {
	t.Parallel()

	var cfg struct {
		Host string `bind:"host,required"`
	}

	err := bind.New("bind").Bind(&cfg, "", mockSource{"host": {}})
	if err == nil {
		t.Fatal("should have returned an error")
	}

	if want := "required"; !strings.Contains(err.Error(), want) {
		t.Errorf("want match for %q; got %q", want, err)
	}
}

func TestBinder_Caching(t *testing.T) {
	b := bind.New("bind", bind.WithCache(true))

	type Config struct {
		Host string `bind:"host"`
		Port int    `bind:"port,default:8080"`
	}

	src := mockSource{
		"host": {"localhost"},
	}

	var cfg1 Config
	err := b.Bind(&cfg1, "", src)
	if err != nil {
		t.Fatalf("on first call: should not have returned an error: %v", err)
	}

	var cfg2 Config
	err = b.Bind(&cfg2, "", src)
	if err != nil {
		t.Fatalf("on second call: should not have returned an error: %v", err)
	}

	if cfg2.Host != "localhost" || cfg2.Port != 8080 {
		t.Errorf("bad result from cached bind: %+v", cfg2)
	}

	allocs := testing.AllocsPerRun(10, func() {
		var c Config
		_ = b.Bind(&c, "", src)
	})

	if allocs > 5 {
		t.Errorf("got %v allocs/run; want at most 5", allocs)
	}
}

type mockTextUnmarshaler string

func (t *mockTextUnmarshaler) UnmarshalText(text []byte) error {
	*t = mockTextUnmarshaler("text:" + string(text))
	return nil
}

var _ encoding.TextUnmarshaler = (*mockTextUnmarshaler)(nil)

type mockTTextUnmarshaler struct {
	V mockTextUnmarshaler
}

type mockTString struct {
	V string
}

type mockTBool struct {
	V bool
}

type mockTInt struct {
	V int
}

type mockTInt8 struct {
	V int8
}

type mockTInt16 struct {
	V int16
}

type mockTInt32 struct {
	V int32
}

type mockTInt64 struct {
	V int64
}

type mockTUint struct {
	V uint
}

type mockTUint8 struct {
	V uint8
}

type mockTUint16 struct {
	V uint16
}

type mockTUint32 struct {
	V uint32
}

type mockTUint64 struct {
	V uint64
}

type mockTFloat32 struct {
	V float32
}

type mockTFloat64 struct {
	V float64
}

type mockTComplex64 struct {
	V complex64
}

type mockTComplex128 struct {
	V complex128
}

type mockTURL struct {
	V url.URL
}

type mockTURLPtr struct {
	V *url.URL
}

type mockTDefault struct {
	V string `bind:",default:foo"`
}

type mockTDefaultQuotes struct {
	V string `bind:",default:'foo,bar'"`
}

type mockTDefaultSliceSplit struct {
	V []string `bind:",split:';',default:'a;b'"`
}

type mockTRequired struct {
	V string `bind:",required"`
}

type mockTRequiredWithDefault struct {
	V int `bind:",required,default:42"`
}

type mockTIgnored struct {
	V string `bind:"-"`
}

type mockTUnexported struct {
	v string //nolint:unused
}

type mockTCustomName struct {
	Foo string `bind:"BAR"`
}

type mockTSnakeCase struct {
	FooBar string
}

type mockTSliceString struct {
	V []string
}

type mockTSliceInt struct {
	V []int
}

type mockTSliceCustomSplit struct {
	V []string `bind:",split:';'"`
}

type mockTSliceByte struct {
	V []byte
}

type mockTSliceByteHex struct {
	V []byte `bind:",format:hex"`
}

type mockTSliceByteBase64 struct {
	V []byte `bind:",format:base64"`
}

type mockTPtrString struct {
	V *string
}

type mockTPtrPtrInt struct {
	V **int
}

type MockTInner struct {
	V string
}

type mockTNested struct {
	Nested MockTInner
}

type mockTNestedCustomPrefix struct {
	Foo MockTInner `bind:",prefix:BAR_"`
}

type mockTNestedEmptyPrefix struct {
	Foo MockTInner `bind:",prefix:''"`
}

type mockTInline struct {
	MockTInner `bind:",inline"`
}

type mockTDuration struct {
	V time.Duration
}

type mockTDurationUnitS struct {
	V time.Duration `bind:",unit:s"`
}

type mockTDurationUnitNs struct {
	V time.Duration `bind:",unit:ns"`
}

type mockTDurationUnitUs struct {
	V time.Duration `bind:",unit:us"`
}

type mockTDurationUnitMicro struct {
	V time.Duration `bind:",unit:μs"`
}

type mockTDurationUnitMs struct {
	V time.Duration `bind:",unit:ms"`
}

type mockTDurationUnitM struct {
	V time.Duration `bind:",unit:m"`
}

type mockTDurationUnitH struct {
	V time.Duration `bind:",unit:h"`
}

type mockTDurationUnitInvalid struct {
	V time.Duration `bind:",unit:invalid"`
}

type mockTTime struct {
	V time.Time
}

type mockTTimeFormatDate struct {
	V time.Time `bind:",format:date"`
}

type mockTTimeFormatDateTime struct {
	V time.Time `bind:",format:dateTime"`
}

type mockTTimeFormatTime struct {
	V time.Time `bind:",format:time"`
}

type mockTTimeFormatUnix struct {
	V time.Time `bind:",format:unix"`
}

type mockTTimeFormatUnixUnit struct {
	V time.Time `bind:",format:unix,unit:ms"`
}

type mockTTimeFormatUnixUnitS struct {
	V time.Time `bind:",format:unix,unit:s"`
}

type mockTTimeFormatUnixUnitUs struct {
	V time.Time `bind:",format:unix,unit:us"`
}

type mockTTimeFormatUnixUnitMicro struct {
	V time.Time `bind:",format:unix,unit:μs"`
}

type mockTTimeFormatUnixUnitInvalid struct {
	V time.Time `bind:",format:unix,unit:invalid"`
}

type mockTTrimOptions struct {
	V string `bind:", default:foo"`
}

type mockTNestedPtr struct {
	Nested *MockTInner
}

type mockTNestedDoublePtr struct {
	Nested **MockTInner
}

type mockTLocation struct {
	V time.Location
}

type mockTLocationPtr struct {
	V *time.Location
}

func bindAny(b *bind.Binder, give any, prefix string, src bind.Source) error {
	switch v := give.(type) {
	case *mockTBool:
		return b.Bind(v, prefix, src)
	case *mockTComplex128:
		return b.Bind(v, prefix, src)
	case *mockTComplex64:
		return b.Bind(v, prefix, src)
	case *mockTCustomName:
		return b.Bind(v, prefix, src)
	case *mockTDefault:
		return b.Bind(v, prefix, src)
	case *mockTDefaultQuotes:
		return b.Bind(v, prefix, src)
	case *mockTDefaultSliceSplit:
		return b.Bind(v, prefix, src)
	case *mockTDuration:
		return b.Bind(v, prefix, src)
	case *mockTDurationUnitH:
		return b.Bind(v, prefix, src)
	case *mockTDurationUnitInvalid:
		return b.Bind(v, prefix, src)
	case *mockTDurationUnitM:
		return b.Bind(v, prefix, src)
	case *mockTDurationUnitMicro:
		return b.Bind(v, prefix, src)
	case *mockTDurationUnitMs:
		return b.Bind(v, prefix, src)
	case *mockTDurationUnitNs:
		return b.Bind(v, prefix, src)
	case *mockTDurationUnitS:
		return b.Bind(v, prefix, src)
	case *mockTDurationUnitUs:
		return b.Bind(v, prefix, src)
	case *mockTFloat32:
		return b.Bind(v, prefix, src)
	case *mockTFloat64:
		return b.Bind(v, prefix, src)
	case *mockTIgnored:
		return b.Bind(v, prefix, src)
	case *mockTInline:
		return b.Bind(v, prefix, src)
	case *mockTInt:
		return b.Bind(v, prefix, src)
	case *mockTInt16:
		return b.Bind(v, prefix, src)
	case *mockTInt32:
		return b.Bind(v, prefix, src)
	case *mockTInt64:
		return b.Bind(v, prefix, src)
	case *mockTInt8:
		return b.Bind(v, prefix, src)
	case *mockTLocation:
		return b.Bind(v, prefix, src)
	case *mockTLocationPtr:
		return b.Bind(v, prefix, src)
	case *mockTNested:
		return b.Bind(v, prefix, src)
	case *mockTNestedCustomPrefix:
		return b.Bind(v, prefix, src)
	case *mockTNestedDoublePtr:
		return b.Bind(v, prefix, src)
	case *mockTNestedEmptyPrefix:
		return b.Bind(v, prefix, src)
	case *mockTNestedPtr:
		return b.Bind(v, prefix, src)
	case *mockTPtrPtrInt:
		return b.Bind(v, prefix, src)
	case *mockTPtrString:
		return b.Bind(v, prefix, src)
	case *mockTRequired:
		return b.Bind(v, prefix, src)
	case *mockTRequiredWithDefault:
		return b.Bind(v, prefix, src)
	case *mockTSliceByte:
		return b.Bind(v, prefix, src)
	case *mockTSliceByteBase64:
		return b.Bind(v, prefix, src)
	case *mockTSliceByteHex:
		return b.Bind(v, prefix, src)
	case *mockTSliceCustomSplit:
		return b.Bind(v, prefix, src)
	case *mockTSliceInt:
		return b.Bind(v, prefix, src)
	case *mockTSliceString:
		return b.Bind(v, prefix, src)
	case *mockTSnakeCase:
		return b.Bind(v, prefix, src)
	case *mockTString:
		return b.Bind(v, prefix, src)
	case *mockTTextUnmarshaler:
		return b.Bind(v, prefix, src)
	case *mockTTime:
		return b.Bind(v, prefix, src)
	case *mockTTimeFormatDate:
		return b.Bind(v, prefix, src)
	case *mockTTimeFormatDateTime:
		return b.Bind(v, prefix, src)
	case *mockTTimeFormatTime:
		return b.Bind(v, prefix, src)
	case *mockTTimeFormatUnix:
		return b.Bind(v, prefix, src)
	case *mockTTimeFormatUnixUnit:
		return b.Bind(v, prefix, src)
	case *mockTTimeFormatUnixUnitInvalid:
		return b.Bind(v, prefix, src)
	case *mockTTimeFormatUnixUnitMicro:
		return b.Bind(v, prefix, src)
	case *mockTTimeFormatUnixUnitS:
		return b.Bind(v, prefix, src)
	case *mockTTimeFormatUnixUnitUs:
		return b.Bind(v, prefix, src)
	case *mockTTrimOptions:
		return b.Bind(v, prefix, src)
	case *mockTURL:
		return b.Bind(v, prefix, src)
	case *mockTURLPtr:
		return b.Bind(v, prefix, src)
	case *mockTUint:
		return b.Bind(v, prefix, src)
	case *mockTUint16:
		return b.Bind(v, prefix, src)
	case *mockTUint32:
		return b.Bind(v, prefix, src)
	case *mockTUint64:
		return b.Bind(v, prefix, src)
	case *mockTUint8:
		return b.Bind(v, prefix, src)
	case *mockTUnexported:
		return b.Bind(v, prefix, src)
	default:
		panic(fmt.Sprintf("unsupported type in test: %T", give))
	}
}

func TestBinder_TypeTests(t *testing.T) {
	t.Parallel()

	u, _ := url.Parse("http://foo.com/bar")

	b := bind.New("bind", bind.WithTransformer(snake.ToUpper))

	tests := []struct {
		name    string
		vars    map[string]string
		give    any
		want    any
		wantErr bool
	}{
		{
			name: "string",
			vars: map[string]string{"V": "foo"},
			give: &mockTString{},
			want: &mockTString{"foo"},
		},
		{
			name: "bool",
			vars: map[string]string{"V": "true"},
			give: &mockTBool{},
			want: &mockTBool{true},
		},
		{
			name: "int",
			vars: map[string]string{"V": "42"},
			give: &mockTInt{},
			want: &mockTInt{42},
		},
		{
			name: "int8",
			vars: map[string]string{"V": "42"},
			give: &mockTInt8{},
			want: &mockTInt8{42},
		},
		{
			name: "int16",
			vars: map[string]string{"V": "42"},
			give: &mockTInt16{},
			want: &mockTInt16{42},
		},
		{
			name: "int32",
			vars: map[string]string{"V": "42"},
			give: &mockTInt32{},
			want: &mockTInt32{42},
		},
		{
			name: "int64",
			vars: map[string]string{"V": "42"},
			give: &mockTInt64{},
			want: &mockTInt64{42},
		},
		{
			name: "uint",
			vars: map[string]string{"V": "42"},
			give: &mockTUint{},
			want: &mockTUint{42},
		},
		{
			name: "uint8",
			vars: map[string]string{"V": "42"},
			give: &mockTUint8{},
			want: &mockTUint8{42},
		},
		{
			name: "uint16",
			vars: map[string]string{"V": "42"},
			give: &mockTUint16{},
			want: &mockTUint16{42},
		},
		{
			name: "uint32",
			vars: map[string]string{"V": "42"},
			give: &mockTUint32{},
			want: &mockTUint32{42},
		},
		{
			name: "uint64",
			vars: map[string]string{"V": "42"},
			give: &mockTUint64{},
			want: &mockTUint64{42},
		},
		{
			name: "float32",
			vars: map[string]string{"V": "3.14"},
			give: &mockTFloat32{},
			want: &mockTFloat32{3.14},
		},
		{
			name: "float64",
			vars: map[string]string{"V": "3.14"},
			give: &mockTFloat64{},
			want: &mockTFloat64{3.14},
		},
		{
			name: "complex64",
			vars: map[string]string{"V": "5-2i"},
			give: &mockTComplex64{},
			want: &mockTComplex64{complex(5, -2)},
		},
		{
			name: "complex128",
			vars: map[string]string{"V": "5-2i"},
			give: &mockTComplex128{},
			want: &mockTComplex128{complex(5, -2)},
		},
		{
			name: "url",
			vars: map[string]string{"V": "http://foo.com/bar"},
			give: &mockTURL{},
			want: &mockTURL{V: *u},
		},
		{
			name: "url pointer",
			vars: map[string]string{"V": "http://foo.com/bar"},
			give: &mockTURLPtr{},
			want: &mockTURLPtr{V: u},
		},
		{
			name:    "url parse error",
			vars:    map[string]string{"V": "::invalid"},
			give:    &mockTURL{},
			wantErr: true,
		},

		{
			name: "text unmarshaler",
			vars: map[string]string{"V": "foo"},
			give: &mockTTextUnmarshaler{},
			want: &mockTTextUnmarshaler{"text:foo"},
		},

		{
			name: "default",
			vars: map[string]string{},
			give: &mockTDefault{},
			want: &mockTDefault{"foo"},
		},
		{
			name: "explicitly empty string overrides default",
			vars: map[string]string{"V": ""},
			give: &mockTDefault{},
			want: &mockTDefault{""},
		},
		{
			name: "default with quotes",
			vars: map[string]string{},
			give: &mockTDefaultQuotes{},
			want: &mockTDefaultQuotes{"foo,bar"},
		},
		{
			name: "default on slice with split",
			vars: map[string]string{},
			give: &mockTDefaultSliceSplit{},
			want: &mockTDefaultSliceSplit{[]string{"a", "b"}},
		},
		{
			name: "required",
			vars: map[string]string{"V": "foo"},
			give: &mockTRequired{},
			want: &mockTRequired{"foo"},
		},
		{
			name:    "required error",
			vars:    map[string]string{},
			give:    &mockTRequired{},
			wantErr: true,
		},
		{
			name: "required with default",
			vars: map[string]string{},
			give: &mockTRequiredWithDefault{},
			want: &mockTRequiredWithDefault{42},
		},
		{
			name: "required field with empty value",
			vars: map[string]string{"V": ""},
			give: &mockTRequired{},
			want: &mockTRequired{""},
		},
		{
			name: "ignored",
			vars: map[string]string{"V": "foo"},
			give: &mockTIgnored{},
			want: &mockTIgnored{},
		},
		{
			name: "unexported",
			vars: map[string]string{"v": "foo"},
			give: &mockTUnexported{},
			want: &mockTUnexported{},
		},
		{
			name: "custom name",
			vars: map[string]string{"BAR": "foo"},
			give: &mockTCustomName{},
			want: &mockTCustomName{"foo"},
		},
		{
			name: "snake case",
			vars: map[string]string{"FOO_BAR": "baz"},
			give: &mockTSnakeCase{},
			want: &mockTSnakeCase{"baz"},
		},
		{
			name: "slice string",
			vars: map[string]string{"V": "foo,bar"},
			give: &mockTSliceString{},
			want: &mockTSliceString{[]string{"foo", "bar"}},
		},
		{
			name: "slice int",
			vars: map[string]string{"V": "1,2"},
			give: &mockTSliceInt{},
			want: &mockTSliceInt{[]int{1, 2}},
		},
		{
			name: "slice custom split",
			vars: map[string]string{"V": "foo;bar"},
			give: &mockTSliceCustomSplit{},
			want: &mockTSliceCustomSplit{[]string{"foo", "bar"}},
		},
		{
			name: "empty slice",
			vars: map[string]string{"V": ""},
			give: &mockTSliceString{},
			want: &mockTSliceString{[]string{}},
		},
		{
			name: "byte slice",
			vars: map[string]string{"V": "foo"},
			give: &mockTSliceByte{},
			want: &mockTSliceByte{[]byte("foo")},
		},
		{
			name: "byte slice hex",
			vars: map[string]string{"V": "666f6f"},
			give: &mockTSliceByteHex{},
			want: &mockTSliceByteHex{[]byte("foo")},
		},
		{
			name: "byte slice base64",
			vars: map[string]string{"V": "Zm9v"},
			give: &mockTSliceByteBase64{},
			want: &mockTSliceByteBase64{[]byte("foo")},
		},
		{
			name: "pointer",
			vars: map[string]string{"V": "foo"},
			give: &mockTPtrString{},
			want: &mockTPtrString{(func() *string { s := "foo"; return &s }())},
		},
		{
			name: "double pointer",
			vars: map[string]string{"V": "42"},
			give: &mockTPtrPtrInt{},
			want: &mockTPtrPtrInt{
				(func() **int { i := 42; p := &i; return &p }()),
			},
		},
		{
			name: "nested struct",
			vars: map[string]string{"NESTED_V": "foo"},
			give: &mockTNested{},
			want: &mockTNested{Nested: MockTInner{"foo"}},
		},
		{
			name: "nested struct pointer",
			vars: map[string]string{"NESTED_V": "foo"},
			give: &mockTNestedPtr{},
			want: &mockTNestedPtr{Nested: &MockTInner{"foo"}},
		},
		{
			name: "nested struct double pointer",
			vars: map[string]string{"NESTED_V": "foo"},
			give: &mockTNestedDoublePtr{},
			want: &mockTNestedDoublePtr{Nested: func() **MockTInner {
				p := &MockTInner{"foo"}
				return &p
			}()},
		},
		{
			name: "nested struct with custom prefix",
			vars: map[string]string{"BAR_V": "foo"},
			give: &mockTNestedCustomPrefix{},
			want: &mockTNestedCustomPrefix{Foo: MockTInner{"foo"}},
		},
		{
			name: "nested struct with empty prefix",
			vars: map[string]string{"V": "foo"},
			give: &mockTNestedEmptyPrefix{},
			want: &mockTNestedEmptyPrefix{Foo: MockTInner{"foo"}},
		},
		{
			name: "inline struct",
			vars: map[string]string{"V": "foo"},
			give: &mockTInline{},
			want: &mockTInline{MockTInner: MockTInner{"foo"}},
		},
		{
			name: "global prefix",
			vars: map[string]string{"APP_V": "foo"},
			give: &mockTString{},
			want: &mockTString{"foo"},
		},
		{
			name: "duration",
			vars: map[string]string{"V": "1m"},
			give: &mockTDuration{},
			want: &mockTDuration{time.Minute},
		},
		{
			name: "duration with unit s",
			vars: map[string]string{"V": "5"},
			give: &mockTDurationUnitS{},
			want: &mockTDurationUnitS{5 * time.Second},
		},
		{
			name: "duration with unit ns",
			vars: map[string]string{"V": "5"},
			give: &mockTDurationUnitNs{},
			want: &mockTDurationUnitNs{5 * time.Nanosecond},
		},
		{
			name: "duration with unit us",
			vars: map[string]string{"V": "5"},
			give: &mockTDurationUnitUs{},
			want: &mockTDurationUnitUs{5 * time.Microsecond},
		},
		{
			name: "duration with unit μs",
			vars: map[string]string{"V": "5"},
			give: &mockTDurationUnitMicro{},
			want: &mockTDurationUnitMicro{5 * time.Microsecond},
		},
		{
			name: "duration with unit ms",
			vars: map[string]string{"V": "5"},
			give: &mockTDurationUnitMs{},
			want: &mockTDurationUnitMs{5 * time.Millisecond},
		},
		{
			name: "duration with unit m",
			vars: map[string]string{"V": "5"},
			give: &mockTDurationUnitM{},
			want: &mockTDurationUnitM{5 * time.Minute},
		},
		{
			name: "duration with unit h",
			vars: map[string]string{"V": "5"},
			give: &mockTDurationUnitH{},
			want: &mockTDurationUnitH{5 * time.Hour},
		},
		{
			name:    "duration with invalid unit",
			vars:    map[string]string{"V": "5"},
			give:    &mockTDurationUnitInvalid{},
			wantErr: true,
		},
		{
			name: "time rfc3339",
			vars: map[string]string{"V": "2025-10-08T22:13:00Z"},
			give: &mockTTime{},
			want: &mockTTime{time.Date(2025, 10, 8, 22, 13, 0, 0, time.UTC)},
		},
		{
			name: "time with format date",
			vars: map[string]string{"V": "2025-10-08"},
			give: &mockTTimeFormatDate{},
			want: &mockTTimeFormatDate{
				time.Date(2025, 10, 8, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "time with format datetime",
			vars: map[string]string{"V": "2025-09-14 06:45:00"},
			give: &mockTTimeFormatDateTime{},
			want: &mockTTimeFormatDateTime{
				time.Date(2025, 9, 14, 6, 45, 0, 0, time.UTC),
			},
		},
		{
			name: "time with format time",
			vars: map[string]string{"V": "22:13:00"},
			give: &mockTTimeFormatTime{},
			want: &mockTTimeFormatTime{
				time.Date(0, 1, 1, 22, 13, 0, 0, time.UTC),
			},
		},
		{
			name: "time unix seconds",
			vars: map[string]string{"V": "1760000000"},
			give: &mockTTimeFormatUnix{},
			want: &mockTTimeFormatUnix{time.Unix(1760000000, 0)},
		},
		{
			name: "time unix milliseconds",
			vars: map[string]string{"V": "1760000000000"},
			give: &mockTTimeFormatUnixUnit{},
			want: &mockTTimeFormatUnixUnit{time.UnixMilli(1760000000000)},
		},
		{
			name: "time unix explicitly seconds",
			vars: map[string]string{"V": "1760000000"},
			give: &mockTTimeFormatUnixUnitS{},
			want: &mockTTimeFormatUnixUnitS{time.Unix(1760000000, 0)},
		},
		{
			name: "time unix microseconds (us)",
			vars: map[string]string{"V": "1760000000000000"},
			give: &mockTTimeFormatUnixUnitUs{},
			want: &mockTTimeFormatUnixUnitUs{time.UnixMicro(1760000000000000)},
		},
		{
			name: "time unix microseconds (μs)",
			vars: map[string]string{"V": "1760000000000000"},
			give: &mockTTimeFormatUnixUnitMicro{},
			want: &mockTTimeFormatUnixUnitMicro{
				time.UnixMicro(1760000000000000),
			},
		},
		{
			name:    "time unix invalid unit",
			vars:    map[string]string{"V": "1760000000"},
			give:    &mockTTimeFormatUnixUnitInvalid{},
			wantErr: true,
		},
		{
			name: "not set keeps original value",
			vars: map[string]string{},
			give: &mockTString{"foo"},
			want: &mockTString{"foo"},
		},
		{
			name: "trim option keys",
			vars: map[string]string{},
			give: &mockTTrimOptions{},
			want: &mockTTrimOptions{"foo"},
		},
		{
			name:    "parse error int",
			vars:    map[string]string{"V": "foo"},
			give:    &mockTInt{},
			wantErr: true,
		},
		{
			name:    "parse error bool",
			vars:    map[string]string{"V": "foo"},
			give:    &mockTBool{},
			wantErr: true,
		},
		{
			name:    "parse error time",
			vars:    map[string]string{"V": "foo"},
			give:    &mockTTime{},
			wantErr: true,
		},
		{
			name:    "parse error duration",
			vars:    map[string]string{"V": "foo"},
			give:    &mockTDuration{},
			wantErr: true,
		},
		{
			name: "location",
			vars: map[string]string{"V": "UTC"},
			give: &mockTLocation{},
			want: &mockTLocation{*time.UTC},
		},
		{
			name: "location pointer",
			vars: map[string]string{"V": "UTC"},
			give: &mockTLocationPtr{},
			want: &mockTLocationPtr{time.UTC},
		},
		{
			name:    "parse error location",
			vars:    map[string]string{"V": "Invalid/Timezone"},
			give:    &mockTLocation{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prefix := ""
			if tt.name == "global prefix" {
				prefix = "APP_"
			}

			src := mockSource{}
			for k, v := range tt.vars {
				src[k] = []string{v}
			}

			err := bindAny(b, tt.give, prefix, src)
			if tt.wantErr {
				if err == nil {
					t.Fatal("should have returned an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}
			if !reflect.DeepEqual(tt.give, tt.want) {
				t.Errorf("got %v; want %v", tt.give, tt.want)
			}
		})
	}
}

// An optional section reached through a pointer must stay nil unless the
// source actually supplies something for it. Materializing it regardless
// would make `cfg.Section != nil` a useless test.
func TestBinder_OptionalNestedPointer(t *testing.T) {
	t.Parallel()

	type TLS struct {
		Cert string `bind:"cert"`
	}
	type Config struct {
		TLS  *TLS `bind:"tls"`
		Host string
	}

	tests := []struct {
		name string
		src  mockSource
		want bool
	}{
		{"nothing", mockSource{}, false},
		{"unrelated key", mockSource{"Host": {"example.com"}}, false},
		{"section supplied", mockSource{"tls_cert": {"/etc/cert.pem"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var cfg Config
			if err := bind.New("bind").Bind(&cfg, "", tt.src); err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}

			if got := cfg.TLS != nil; got != tt.want {
				t.Fatalf("allocated: got %t; want %t", got, tt.want)
			}

			if tt.want && cfg.TLS.Cert != "/etc/cert.pem" {
				t.Errorf("cert: got %q; want %q", cfg.TLS.Cert, "/etc/cert.pem")
			}
		})
	}
}

// A default inside the section counts as content: the author asked for that
// value to exist whenever the section does.
func TestBinder_NestedPointerWithDefault(t *testing.T) {
	t.Parallel()

	type TLS struct {
		Port int `bind:"port,default:443"`
	}
	var cfg struct {
		TLS *TLS `bind:"tls"`
	}

	if err := bind.New("bind").Bind(&cfg, "", mockSource{}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if cfg.TLS == nil {
		t.Fatal("got nil; want the section its default implies")
	}

	if cfg.TLS.Port != 443 {
		t.Errorf("port: got %d; want 443", cfg.TLS.Port)
	}
}

// A pointer that the caller already set is filled in place, not replaced.
func TestBinder_PresetNestedPointer(t *testing.T) {
	t.Parallel()

	type TLS struct {
		Cert string `bind:"cert"`
		Key  string `bind:"key"`
	}
	preset := &TLS{Key: "/etc/key.pem"}
	cfg := struct {
		TLS *TLS `bind:"tls"`
	}{TLS: preset}

	src := mockSource{"tls_cert": {"/etc/cert.pem"}}
	if err := bind.New("bind").Bind(&cfg, "", src); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if cfg.TLS != preset {
		t.Error("the preset pointer was replaced")
	}

	if cfg.TLS.Key != "/etc/key.pem" {
		t.Errorf("key: got %q; want it preserved", cfg.TLS.Key)
	}

	if cfg.TLS.Cert != "/etc/cert.pem" {
		t.Errorf("cert: got %q; want it bound", cfg.TLS.Cert)
	}
}

// An embedded pointer that inlines its keys follows the same rule.
func TestBinder_InlineNestedPointer(t *testing.T) {
	t.Parallel()

	type Common struct {
		Region string `bind:"region"`
	}
	type Config struct {
		*Common `bind:",inline"`
		Name    string `bind:"name"`
	}

	t.Run("absent", func(t *testing.T) {
		var cfg Config
		src := mockSource{"name": {"svc"}}
		if err := bind.New("bind").Bind(&cfg, "", src); err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if cfg.Common != nil {
			t.Error("allocated an inline section with nothing to bind")
		}
	})

	t.Run("supplied", func(t *testing.T) {
		var cfg Config
		src := mockSource{"region": {"eu-central-1"}}
		if err := bind.New("bind").Bind(&cfg, "", src); err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if cfg.Common == nil {
			t.Fatal("got nil; want the inlined section")
		}
		if cfg.Common.Region != "eu-central-1" {
			t.Errorf("region: got %q; want %q",
				cfg.Common.Region, "eu-central-1")
		}
	})
}
