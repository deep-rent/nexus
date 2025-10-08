package env_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/deep-rent/nexus/env"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type reverse string

func (r *reverse) UnmarshalEnv(v string) error {
	runes := []rune(v)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	*r = reverse(string(runes))
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
type TURL struct {
	V url.URL
}
type TURLPtr struct {
	V *url.URL
}
type TReverse struct {
	V reverse
}
type TReversePtr struct {
	V *reverse
}
type TDefault struct {
	V string `env:",default:foo"`
}
type TDefaultQuotes struct {
	V string `env:",default:'foo,bar'"`
}
type TRequired struct {
	V string `env:",required"`
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
type TDurationUnit struct {
	V time.Duration `env:",unit:s"`
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
type TUnknownTag struct {
	V string `env:",foo:bar"`
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
			in:   &TReverse{},
			want: &TReverse{"oof"},
		},
		{
			name: "unmarshaler pointer",
			vars: map[string]string{"V": "foo"},
			in:   &TReversePtr{},
			want: &TReversePtr{V: new(reverse)},
		},
		{
			name: "default",
			vars: map[string]string{},
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
			name: "duration with unit",
			vars: map[string]string{"V": "5"},
			in:   &TDurationUnit{},
			want: &TDurationUnit{5 * time.Second},
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
			vars: map[string]string{"V": "2025-10-08 22:13:00"},
			in:   &TTimeFormatDateTime{},
			want: &TTimeFormatDateTime{time.Date(2025, 10, 8, 22, 13, 0, 0, time.UTC)},
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
			name: "not set keeps original value",
			vars: map[string]string{},
			in:   &TString{"foo"},
			want: &TString{"foo"},
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := append(tc.opts, env.WithLookup(func(k string) (string, bool) {
				v, ok := tc.vars[k]
				return v, ok
			}))

			if tc.name == "unmarshaler pointer" {
				p := new(reverse)
				*p = "oof"
				tc.want.(*TReversePtr).V = p
			}

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
			name: "simple expansion",
			vars: map[string]string{"FOO": "bar"},
			in:   "hello ${FOO}",
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
			name: "with prefix",
			vars: map[string]string{"APP_FOO": "bar"},
			opts: []env.Option{env.WithPrefix("APP_")},
			in:   "${FOO}",
			want: "bar",
		},
		{
			name:    "variable not set",
			vars:    map[string]string{},
			in:      "${FOO}",
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
			in:   "user=${USER}, pass=$$ECRET, dsn=${USER}@${HOST}:${PORT}",
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
