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

package env_test

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/env"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type upperUnmarshaller string

func (u *upperUnmarshaller) UnmarshalEnv(v string) error {
	*u = upperUnmarshaller(strings.ToUpper(v))
	return nil
}

type errorUnmarshaler struct{}

func (e *errorUnmarshaler) UnmarshalEnv(v string) error {
	return assert.AnError
}

type checkUnmarshaler string

func (c checkUnmarshaler) UnmarshalEnv(v string) error {
	if v == "invalid" {
		return assert.AnError
	}
	return nil
}

type TString struct {
	V string
}

type TBool struct {
	V bool
}

type TInt struct {
	V int
}

type TInt8 struct {
	V int8
}

type TInt16 struct {
	V int16
}

type TInt32 struct {
	V int32
}

type TInt64 struct {
	V int64
}

type TUint struct {
	V uint
}

type TUint8 struct {
	V uint8
}

type TUint16 struct {
	V uint16
}

type TUint32 struct {
	V uint32
}

type TUint64 struct {
	V uint64
}

type TFloat32 struct {
	V float32
}

type TFloat64 struct {
	V float64
}

type TComplex64 struct {
	V complex64
}

type TComplex128 struct {
	V complex128
}

type TURL struct {
	V url.URL
}

type TURLPtr struct {
	V *url.URL
}

type TUpper struct {
	V upperUnmarshaller
}

type TUpperPtr struct {
	V *upperUnmarshaller
}

type TDefault struct {
	V string `env:",default:foo"`
}

type TDefaultQuotes struct {
	V string `env:",default:'foo,bar'"`
}

type TDefaultSliceSplit struct {
	V []string `env:",split:';',default:'a;b'"`
}

type TRequired struct {
	V string `env:",required"`
}

type TRequiredWithDefault struct {
	V int `env:",required,default:42"`
}

type TIgnored struct {
	V string `env:"-"`
}

type TUnexported struct {
	v string
}

type TCustomName struct {
	Foo string `env:"BAR"`
}

type TSnakeCase struct {
	FooBar string
}

type TSliceString struct {
	V []string
}

type TSliceInt struct {
	V []int
}

type TSliceCustomSplit struct {
	V []string `env:",split:';'"`
}

type TSliceByte struct {
	V []byte
}

type TSliceByteHex struct {
	V []byte `env:",format:hex"`
}

type TSliceByteBase64 struct {
	V []byte `env:",format:base64"`
}

type TPtrString struct {
	V *string
}

type TPtrPtrInt struct {
	V **int
}

type TInner struct {
	V string
}

type TNested struct {
	Nested TInner
}

type TNestedCustomPrefix struct {
	Foo TInner `env:",prefix:BAR_"`
}

type TNestedEmptyPrefix struct {
	Foo TInner `env:",prefix:''"`
}

type TInline struct {
	TInner `env:",inline"`
}

type TDuration struct {
	V time.Duration
}

type TDurationUnitS struct {
	V time.Duration `env:",unit:s"`
}

type TDurationUnitNs struct {
	V time.Duration `env:",unit:ns"`
}

type TDurationUnitUs struct {
	V time.Duration `env:",unit:us"`
}

type TDurationUnitMicro struct {
	V time.Duration `env:",unit:μs"`
}

type TDurationUnitMs struct {
	V time.Duration `env:",unit:ms"`
}

type TDurationUnitM struct {
	V time.Duration `env:",unit:m"`
}

type TDurationUnitH struct {
	V time.Duration `env:",unit:h"`
}

type TDurationUnitInvalid struct {
	V time.Duration `env:",unit:invalid"`
}

type TTime struct {
	V time.Time
}

type TTimeFormatDate struct {
	V time.Time `env:",format:date"`
}

type TTimeFormatDateTime struct {
	V time.Time `env:",format:dateTime"`
}

type TTimeFormatTime struct {
	V time.Time `env:",format:time"`
}

type TTimeFormatUnix struct {
	V time.Time `env:",format:unix"`
}

type TTimeFormatUnixUnit struct {
	V time.Time `env:",format:unix,unit:ms"`
}

type TTimeFormatUnixUnitS struct {
	V time.Time `env:",format:unix,unit:s"`
}

type TTimeFormatUnixUnitUs struct {
	V time.Time `env:",format:unix,unit:us"`
}

type TTimeFormatUnixUnitMicro struct {
	V time.Time `env:",format:unix,unit:μs"`
}

type TTimeFormatUnixUnitInvalid struct {
	V time.Time `env:",format:unix,unit:invalid"`
}

type TUnknownTag struct {
	V string `env:",foo:bar"`
}

type TTrimOptions struct {
	V string `env:", default:foo"`
}

type TNestedPtr struct {
	Nested *TInner
}

type TNestedDoublePtr struct {
	Nested **TInner
}

type TLocation struct {
	V time.Location
}

type TLocationPtr struct {
	V *time.Location
}

func TestUnmarshal(t *testing.T) {
	u, err := url.Parse("http://foo.com/bar")
	require.NoError(t, err)

	type test struct {
		name    string
		vars    map[string]string
		opts    []env.Option
		in      any
		want    any
		wantErr bool
	}

	tests := []test{
		{
			name: "string",
			vars: map[string]string{"V": "foo"},
			in:   &TString{},
			want: &TString{"foo"},
		},
		{
			name: "bool",
			vars: map[string]string{"V": "true"},
			in:   &TBool{},
			want: &TBool{true},
		},
		{
			name: "int",
			vars: map[string]string{"V": "42"},
			in:   &TInt{},
			want: &TInt{42},
		},
		{
			name: "int8",
			vars: map[string]string{"V": "42"},
			in:   &TInt8{},
			want: &TInt8{42},
		},
		{
			name: "int16",
			vars: map[string]string{"V": "42"},
			in:   &TInt16{},
			want: &TInt16{42},
		},
		{
			name: "int32",
			vars: map[string]string{"V": "42"},
			in:   &TInt32{},
			want: &TInt32{42},
		},
		{
			name: "int64",
			vars: map[string]string{"V": "42"},
			in:   &TInt64{},
			want: &TInt64{42},
		},
		{
			name: "uint",
			vars: map[string]string{"V": "42"},
			in:   &TUint{},
			want: &TUint{42},
		},
		{
			name: "uint8",
			vars: map[string]string{"V": "42"},
			in:   &TUint8{},
			want: &TUint8{42},
		},
		{
			name: "uint16",
			vars: map[string]string{"V": "42"},
			in:   &TUint16{},
			want: &TUint16{42},
		},
		{
			name: "uint32",
			vars: map[string]string{"V": "42"},
			in:   &TUint32{},
			want: &TUint32{42},
		},
		{
			name: "uint64",
			vars: map[string]string{"V": "42"},
			in:   &TUint64{},
			want: &TUint64{42},
		},
		{
			name: "float32",
			vars: map[string]string{"V": "3.14"},
			in:   &TFloat32{},
			want: &TFloat32{3.14},
		},
		{
			name: "float64",
			vars: map[string]string{"V": "3.14"},
			in:   &TFloat64{},
			want: &TFloat64{3.14},
		},
		{
			name: "complex64",
			vars: map[string]string{"V": "5-2i"},
			in:   &TComplex64{},
			want: &TComplex64{complex(5, -2)},
		},
		{
			name: "complex128",
			vars: map[string]string{"V": "5-2i"},
			in:   &TComplex64{},
			want: &TComplex64{complex(5, -2)},
		},
		{
			name: "url",
			vars: map[string]string{"V": "http://foo.com/bar"},
			in:   &TURL{},
			want: &TURL{V: *u},
		},
		{
			name: "url pointer",
			vars: map[string]string{"V": "http://foo.com/bar"},
			in:   &TURLPtr{},
			want: &TURLPtr{V: u},
		},
		{
			name:    "url parse error",
			vars:    map[string]string{"V": "::invalid"},
			in:      &TURL{},
			wantErr: true,
		},
		{
			name: "unmarshaler",
			vars: map[string]string{"V": "foo"},
			in:   &TUpper{},
			want: &TUpper{"FOO"},
		},
		{
			name: "unmarshaler pointer",
			vars: map[string]string{"V": "foo"},
			in:   &TUpperPtr{},
			want: &TUpperPtr{V: func() *upperUnmarshaller {
				p := upperUnmarshaller("FOO")
				return &p
			}()},
		},
		{
			name:    "value-receiver unmarshaler error",
			vars:    map[string]string{"V": "invalid"},
			in:      &struct{ V checkUnmarshaler }{},
			wantErr: true,
		},
		{
			name:    "unmarshaler error",
			vars:    map[string]string{"V": "foo"},
			in:      &struct{ V errorUnmarshaler }{},
			wantErr: true,
		},
		{
			name: "default",
			vars: map[string]string{},
			in:   &TDefault{},
			want: &TDefault{"foo"},
		},
		{
			name: "explicitly empty string uses default",
			vars: map[string]string{"V": ""},
			in:   &TDefault{},
			want: &TDefault{"foo"},
		},
		{
			name: "default with quotes",
			vars: map[string]string{},
			in:   &TDefaultQuotes{},
			want: &TDefaultQuotes{"foo,bar"},
		},
		{
			name: "default on slice with split",
			vars: map[string]string{},
			in:   &TDefaultSliceSplit{},
			want: &TDefaultSliceSplit{[]string{"a", "b"}},
		},
		{
			name: "required",
			vars: map[string]string{"V": "foo"},
			in:   &TRequired{},
			want: &TRequired{"foo"},
		},
		{
			name:    "required error",
			vars:    map[string]string{},
			in:      &TRequired{},
			wantErr: true,
		},
		{
			name: "required with default",
			vars: map[string]string{},
			in:   &TRequiredWithDefault{},
			want: &TRequiredWithDefault{42},
		},
		{
			name: "required field with empty value",
			vars: map[string]string{"V": ""},
			in:   &TRequired{},
			want: &TRequired{""},
		},
		{
			name: "ignored",
			vars: map[string]string{"V": "foo"},
			in:   &TIgnored{},
			want: &TIgnored{},
		},
		{
			name: "unexported",
			vars: map[string]string{"v": "foo"},
			in:   &TUnexported{},
			want: &TUnexported{},
		},
		{
			name: "custom name",
			vars: map[string]string{"BAR": "foo"},
			in:   &TCustomName{},
			want: &TCustomName{"foo"},
		},
		{
			name: "snake case",
			vars: map[string]string{"FOO_BAR": "baz"},
			in:   &TSnakeCase{},
			want: &TSnakeCase{"baz"},
		},
		{
			name: "slice string",
			vars: map[string]string{"V": "foo,bar"},
			in:   &TSliceString{},
			want: &TSliceString{[]string{"foo", "bar"}},
		},
		{
			name: "slice int",
			vars: map[string]string{"V": "1,2"},
			in:   &TSliceInt{},
			want: &TSliceInt{[]int{1, 2}},
		},
		{
			name: "slice custom split",
			vars: map[string]string{"V": "foo;bar"},
			in:   &TSliceCustomSplit{},
			want: &TSliceCustomSplit{[]string{"foo", "bar"}},
		},
		{
			name: "empty slice",
			vars: map[string]string{"V": ""},
			in:   &TSliceString{},
			want: &TSliceString{[]string{}},
		},
		{
			name: "byte slice",
			vars: map[string]string{"V": "foo"},
			in:   &TSliceByte{},
			want: &TSliceByte{[]byte("foo")},
		},
		{
			name: "byte slice hex",
			vars: map[string]string{"V": "666f6f"},
			in:   &TSliceByteHex{},
			want: &TSliceByteHex{[]byte("foo")},
		},
		{
			name: "byte slice base64",
			vars: map[string]string{"V": "Zm9v"},
			in:   &TSliceByteBase64{},
			want: &TSliceByteBase64{[]byte("foo")},
		},
		{
			name: "pointer",
			vars: map[string]string{"V": "foo"},
			in:   &TPtrString{},
			want: &TPtrString{(func() *string { s := "foo"; return &s }())},
		},
		{
			name: "double pointer",
			vars: map[string]string{"V": "42"},
			in:   &TPtrPtrInt{},
			want: &TPtrPtrInt{(func() **int { i := 42; p := &i; return &p }())},
		},
		{
			name: "nested struct",
			vars: map[string]string{"NESTED_V": "foo"},
			in:   &TNested{},
			want: &TNested{Nested: TInner{"foo"}},
		},
		{
			name: "nested struct pointer",
			vars: map[string]string{"NESTED_V": "foo"},
			in:   &TNestedPtr{},
			want: &TNestedPtr{Nested: &TInner{"foo"}},
		},
		{
			name: "nested struct double pointer",
			vars: map[string]string{"NESTED_V": "foo"},
			in:   &TNestedDoublePtr{},
			want: &TNestedDoublePtr{Nested: func() **TInner {
				p := &TInner{"foo"}
				return &p
			}()},
		},
		{
			name: "nested struct with custom prefix",
			vars: map[string]string{"BAR_V": "foo"},
			in:   &TNestedCustomPrefix{},
			want: &TNestedCustomPrefix{Foo: TInner{"foo"}},
		},
		{
			name: "nested struct with empty prefix",
			vars: map[string]string{"V": "foo"},
			in:   &TNestedEmptyPrefix{},
			want: &TNestedEmptyPrefix{Foo: TInner{"foo"}},
		},
		{
			name: "inline struct",
			vars: map[string]string{"V": "foo"},
			in:   &TInline{},
			want: &TInline{TInner: TInner{"foo"}},
		},
		{
			name: "global prefix",
			vars: map[string]string{"APP_V": "foo"},
			opts: []env.Option{env.WithPrefix("APP_")},
			in:   &TString{},
			want: &TString{"foo"},
		},
		{
			name: "duration",
			vars: map[string]string{"V": "1m"},
			in:   &TDuration{},
			want: &TDuration{time.Minute},
		},
		{
			name: "duration with unit s",
			vars: map[string]string{"V": "5"},
			in:   &TDurationUnitS{},
			want: &TDurationUnitS{5 * time.Second},
		},
		{
			name: "duration with unit ns",
			vars: map[string]string{"V": "5"},
			in:   &TDurationUnitNs{},
			want: &TDurationUnitNs{5 * time.Nanosecond},
		},
		{
			name: "duration with unit us",
			vars: map[string]string{"V": "5"},
			in:   &TDurationUnitUs{},
			want: &TDurationUnitUs{5 * time.Microsecond},
		},
		{
			name: "duration with unit μs",
			vars: map[string]string{"V": "5"},
			in:   &TDurationUnitMicro{},
			want: &TDurationUnitMicro{5 * time.Microsecond},
		},
		{
			name: "duration with unit ms",
			vars: map[string]string{"V": "5"},
			in:   &TDurationUnitMs{},
			want: &TDurationUnitMs{5 * time.Millisecond},
		},
		{
			name: "duration with unit m",
			vars: map[string]string{"V": "5"},
			in:   &TDurationUnitM{},
			want: &TDurationUnitM{5 * time.Minute},
		},
		{
			name: "duration with unit h",
			vars: map[string]string{"V": "5"},
			in:   &TDurationUnitH{},
			want: &TDurationUnitH{5 * time.Hour},
		},
		{
			name:    "duration with invalid unit",
			vars:    map[string]string{"V": "5"},
			in:      &TDurationUnitInvalid{},
			wantErr: true,
		},
		{
			name: "time rfc3339",
			vars: map[string]string{"V": "2025-10-08T22:13:00Z"},
			in:   &TTime{},
			want: &TTime{time.Date(2025, 10, 8, 22, 13, 0, 0, time.UTC)},
		},
		{
			name: "time with format date",
			vars: map[string]string{"V": "2025-10-08"},
			in:   &TTimeFormatDate{},
			want: &TTimeFormatDate{time.Date(2025, 10, 8, 0, 0, 0, 0, time.UTC)},
		},
		{
			name: "time with format datetime",
			vars: map[string]string{"V": "2025-09-14 06:45:00"},
			in:   &TTimeFormatDateTime{},
			want: &TTimeFormatDateTime{time.Date(2025, 9, 14, 6, 45, 0, 0, time.UTC)},
		},
		{
			name: "time with format time",
			vars: map[string]string{"V": "22:13:00"},
			in:   &TTimeFormatTime{},
			want: &TTimeFormatTime{time.Date(0, 1, 1, 22, 13, 0, 0, time.UTC)},
		},
		{
			name: "time unix seconds",
			vars: map[string]string{"V": "1760000000"},
			in:   &TTimeFormatUnix{},
			want: &TTimeFormatUnix{time.Unix(1760000000, 0)},
		},
		{
			name: "time unix milliseconds",
			vars: map[string]string{"V": "1760000000000"},
			in:   &TTimeFormatUnixUnit{},
			want: &TTimeFormatUnixUnit{time.UnixMilli(1760000000000)},
		},
		{
			name: "time unix explicitly seconds",
			vars: map[string]string{"V": "1760000000"},
			in:   &TTimeFormatUnixUnitS{},
			want: &TTimeFormatUnixUnitS{time.Unix(1760000000, 0)},
		},
		{
			name: "time unix microseconds (us)",
			vars: map[string]string{"V": "1760000000000000"},
			in:   &TTimeFormatUnixUnitUs{},
			want: &TTimeFormatUnixUnitUs{time.UnixMicro(1760000000000000)},
		},
		{
			name: "time unix microseconds (μs)",
			vars: map[string]string{"V": "1760000000000000"},
			in:   &TTimeFormatUnixUnitMicro{},
			want: &TTimeFormatUnixUnitMicro{time.UnixMicro(1760000000000000)},
		},
		{
			name:    "time unix invalid unit",
			vars:    map[string]string{"V": "1760000000"},
			in:      &TTimeFormatUnixUnitInvalid{},
			wantErr: true,
		},
		{
			name: "not set keeps original value",
			vars: map[string]string{},
			in:   &TString{"foo"},
			want: &TString{"foo"},
		},
		{
			name: "trim option keys",
			vars: map[string]string{},
			in:   &TTrimOptions{},
			want: &TTrimOptions{"foo"},
		},
		{
			name:    "parse error int",
			vars:    map[string]string{"V": "foo"},
			in:      &TInt{},
			wantErr: true,
		},
		{
			name:    "parse error bool",
			vars:    map[string]string{"V": "foo"},
			in:      &TBool{},
			wantErr: true,
		},
		{
			name:    "parse error time",
			vars:    map[string]string{"V": "foo"},
			in:      &TTime{},
			wantErr: true,
		},
		{
			name:    "parse error duration",
			vars:    map[string]string{"V": "foo"},
			in:      &TDuration{},
			wantErr: true,
		},
		{
			name:    "unknown tag option",
			vars:    map[string]string{},
			in:      &TUnknownTag{},
			wantErr: true,
		},
		{
			name: "location",
			vars: map[string]string{"V": "UTC"},
			in:   &TLocation{},
			want: &TLocation{*time.UTC},
		},
		{
			name: "location pointer",
			vars: map[string]string{"V": "UTC"},
			in:   &TLocationPtr{},
			want: &TLocationPtr{time.UTC},
		},
		{
			name:    "parse error location",
			vars:    map[string]string{"V": "Invalid/Timezone"},
			in:      &TLocation{},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := append(tc.opts, env.WithLookup(func(k string) (string, bool) {
				v, ok := tc.vars[k]
				return v, ok
			}))
			err := env.Unmarshal(tc.in, opts...)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, tc.in)
			}
		})
	}
}

func TestUnmarshalErrors(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		err := env.Unmarshal(nil)
		require.Error(t, err)
	})

	t.Run("not a pointer", func(t *testing.T) {
		var s struct{}
		err := env.Unmarshal(s)
		require.Error(t, err)
	})

	t.Run("not a pointer to a struct", func(t *testing.T) {
		var i int
		err := env.Unmarshal(&i)
		require.Error(t, err)
	})
}

func TestExpand(t *testing.T) {
	type test struct {
		name    string
		vars    map[string]string
		opts    []env.Option
		in      string
		want    string
		wantErr bool
	}

	tests := []test{
		{
			name: "no variables",
			in:   "foo bar baz",
			want: "foo bar baz",
		},
		{
			name: "simple bracket expansion",
			vars: map[string]string{"FOO": "bar"},
			in:   "hello ${FOO}",
			want: "hello bar",
		},
		{
			name: "simple unbracketed expansion",
			vars: map[string]string{"FOO": "bar"},
			in:   "hello $FOO",
			want: "hello bar",
		},
		{
			name: "unbracketed expansion stopping at non-identifier",
			vars: map[string]string{"FOO": "bar"},
			in:   "$FOO-baz",
			want: "bar-baz",
		},
		{
			name: "unbracketed expansion with numbers and underscores",
			vars: map[string]string{"VAR_123": "bar"},
			in:   "hello $VAR_123",
			want: "hello bar",
		},
		{
			name: "multiple expansions",
			vars: map[string]string{"FOO": "bar", "BAZ": "qux"},
			in:   "${FOO} ${BAZ}",
			want: "bar qux",
		},
		{
			name: "escaped dollar sign",
			vars: map[string]string{},
			in:   "this is not a var: $$FOO",
			want: "this is not a var: $FOO",
		},
		{
			name: "lone dollar sign",
			vars: map[string]string{},
			in:   "a lone $ sign",
			want: "a lone $ sign",
		},
		{
			name: "lone dollar sign before number",
			vars: map[string]string{},
			in:   "cost is $5",
			want: "cost is $5",
		},
		{
			name: "variable at start",
			vars: map[string]string{"FOO": "bar"},
			in:   "${FOO} baz",
			want: "bar baz",
		},
		{
			name: "variable at end",
			vars: map[string]string{"FOO": "bar"},
			in:   "baz ${FOO}",
			want: "baz bar",
		},
		{
			name: "bracketed with prefix",
			vars: map[string]string{"APP_FOO": "bar"},
			opts: []env.Option{env.WithPrefix("APP_")},
			in:   "${FOO}",
			want: "bar",
		},
		{
			name: "unbracketed with prefix",
			vars: map[string]string{"APP_FOO": "bar"},
			opts: []env.Option{env.WithPrefix("APP_")},
			in:   "$FOO",
			want: "bar",
		},
		{
			name:    "bracketed variable not set",
			vars:    map[string]string{},
			in:      "${FOO}",
			wantErr: true,
		},
		{
			name:    "unbracketed variable not set",
			vars:    map[string]string{},
			in:      "$FOO",
			wantErr: true,
		},
		{
			name:    "unclosed bracket",
			vars:    map[string]string{},
			in:      "${FOO",
			wantErr: true,
		},
		{
			name: "empty string",
			in:   "",
			want: "",
		},
		{
			name: "complex string",
			vars: map[string]string{"USER": "foo", "HOST": "bar", "PORT": "8080"},
			in:   "user=$USER, pass=$$ECRET, dsn=${USER}@${HOST}:${PORT}",
			want: "user=foo, pass=$ECRET, dsn=foo@bar:8080",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := append(tc.opts, env.WithLookup(func(k string) (string, bool) {
				v, ok := tc.vars[k]
				return v, ok
			}))
			got, err := env.Expand(tc.in, opts...)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

type BenchConfig struct {
	Host    string        `env:",required"`
	Port    int           `env:",default:8080"`
	Timeout time.Duration `env:",unit:s"`
	Debug   bool
	Roles   []string `env:",split:';'"`
}

func BenchmarkUnmarshal(b *testing.B) {
	mockEnv := map[string]string{
		"HOST":    "localhost",
		"PORT":    "9090",
		"TIMEOUT": "30",
		"DEBUG":   "true",
		"ROLES":   "admin;user;guest",
	}

	opts := []env.Option{
		env.WithLookup(func(k string) (string, bool) {
			v, ok := mockEnv[k]
			return v, ok
		}),
	}

	for b.Loop() {
		var cfg BenchConfig
		if err := env.Unmarshal(&cfg, opts...); err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkExpand(b *testing.B) {
	mockEnv := map[string]string{
		"USER": "foo",
		"HOST": "bar",
		"PORT": "8080",
	}

	opts := []env.Option{
		env.WithLookup(func(k string) (string, bool) {
			v, ok := mockEnv[k]
			return v, ok
		}),
	}

	input := "user=$USER, pass=$$ECRET, dsn=${USER}@${HOST}:${PORT}"

	for b.Loop() {
		_, err := env.Expand(input, opts...)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}
