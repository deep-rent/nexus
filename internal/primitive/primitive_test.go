package primitive_test

import (
	"reflect"
	"testing"

	"github.com/deep-rent/nexus/internal/primitive"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	type test struct {
		name    string
		setup   func() reflect.Value
		in      string
		wantErr bool
		assert  func(t *testing.T, v reflect.Value)
	}

	tests := []test{
		{"bool true", func() reflect.Value { var v bool; return reflect.ValueOf(&v).Elem() }, "true", false, func(t *testing.T, v reflect.Value) { assert.True(t, v.Bool()) }},
		{"bool false", func() reflect.Value { var v bool; return reflect.ValueOf(&v).Elem() }, "false", false, func(t *testing.T, v reflect.Value) { assert.False(t, v.Bool()) }},
		{"bool error", func() reflect.Value { var v bool; return reflect.ValueOf(&v).Elem() }, "not-a-bool", true, nil},
		{"string", func() reflect.Value { var v string; return reflect.ValueOf(&v).Elem() }, "hello world", false, func(t *testing.T, v reflect.Value) { assert.Equal(t, "hello world", v.String()) }},
		{"int", func() reflect.Value { var v int; return reflect.ValueOf(&v).Elem() }, "-123", false, func(t *testing.T, v reflect.Value) { assert.Equal(t, int64(-123), v.Int()) }},
		{"int8", func() reflect.Value { var v int8; return reflect.ValueOf(&v).Elem() }, "127", false, func(t *testing.T, v reflect.Value) { assert.Equal(t, int64(127), v.Int()) }},
		{"int8 overflow", func() reflect.Value { var v int8; return reflect.ValueOf(&v).Elem() }, "128", true, nil},
		{"int error", func() reflect.Value { var v int; return reflect.ValueOf(&v).Elem() }, "not-an-int", true, nil},
		{"uint", func() reflect.Value { var v uint; return reflect.ValueOf(&v).Elem() }, "123", false, func(t *testing.T, v reflect.Value) { assert.Equal(t, uint64(123), v.Uint()) }},
		{"uint8", func() reflect.Value { var v uint8; return reflect.ValueOf(&v).Elem() }, "255", false, func(t *testing.T, v reflect.Value) { assert.Equal(t, uint64(255), v.Uint()) }},
		{"uint8 overflow", func() reflect.Value { var v uint8; return reflect.ValueOf(&v).Elem() }, "256", true, nil},
		{"uint error", func() reflect.Value { var v uint; return reflect.ValueOf(&v).Elem() }, "-1", true, nil},
		{"float32", func() reflect.Value { var v float32; return reflect.ValueOf(&v).Elem() }, "123.45", false, func(t *testing.T, v reflect.Value) { assert.InDelta(t, 123.45, v.Float(), 0.001) }},
		{"float64", func() reflect.Value { var v float64; return reflect.ValueOf(&v).Elem() }, "-1.23e4", false, func(t *testing.T, v reflect.Value) { assert.Equal(t, -12300.0, v.Float()) }},
		{"float error", func() reflect.Value { var v float64; return reflect.ValueOf(&v).Elem() }, "not-a-float", true, nil},
		{"complex64", func() reflect.Value { var v complex64; return reflect.ValueOf(&v).Elem() }, "1+2.5i", false, func(t *testing.T, v reflect.Value) { assert.Equal(t, complex(float64(1), float64(2.5)), v.Complex()) }},
		{"complex128", func() reflect.Value { var v complex128; return reflect.ValueOf(&v).Elem() }, "-5.5-10.1i", false, func(t *testing.T, v reflect.Value) { assert.Equal(t, complex(-5.5, -10.1), v.Complex()) }},
		{"complex error", func() reflect.Value { var v complex128; return reflect.ValueOf(&v).Elem() }, "not-complex", true, nil},
		{"unsupported type", func() reflect.Value { var v struct{}; return reflect.ValueOf(&v).Elem() }, "some value", true, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rv := tc.setup()
			err := primitive.Parse(rv, tc.in)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tc.assert != nil {
					tc.assert(t, rv)
				}
			}
		})
	}

	t.Run("panics on non-settable value", func(t *testing.T) {
		var v int
		rv := reflect.ValueOf(v)
		require.False(t, rv.CanSet())
		assert.Panics(t, func() {
			_ = primitive.Parse(rv, "123")
		})
	})
}
