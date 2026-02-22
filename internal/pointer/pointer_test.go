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

package pointer_test

import (
	"reflect"
	"testing"

	"github.com/deep-rent/nexus/internal/pointer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlloc(t *testing.T) {
	t.Run("allocates settable nil pointer", func(t *testing.T) {
		var i *int
		rv := reflect.ValueOf(&i).Elem()

		require.True(t, rv.IsNil(), "precondition: pointer should be nil")
		require.True(t, rv.CanSet(), "precondition: pointer should be settable")

		pointer.Alloc(rv)
		assert.NotNil(t, i, "pointer should now point to a value")
		assert.Equal(t, 0, *i, "value should be the zero value for its type")
	})

	t.Run("panics on non-settable pointer", func(t *testing.T) {
		type foobar struct{ v *int } // nolint:unused
		rv := reflect.ValueOf(foobar{}).FieldByName("v")
		require.False(t, rv.CanSet(), "precondition: value should not be settable")
		assert.Panics(t, func() {
			pointer.Alloc(rv)
		}, "Alloc should panic because it cannot set the pointer")
	})
}

func TestDeref(t *testing.T) {
	type test struct {
		name     string
		setup    func() (in, root reflect.Value)
		wantKind reflect.Kind
		assert   func(t *testing.T, out, root reflect.Value)
	}

	type foobar struct {
		V *int
		v *int
	}

	tests := []test{
		{
			name: "non-pointer value",
			setup: func() (reflect.Value, reflect.Value) {
				v := 42
				return reflect.ValueOf(v), reflect.ValueOf(v)
			},
			wantKind: reflect.Int,
			assert: func(t *testing.T, out, _ reflect.Value) {
				assert.Equal(t, int64(42), out.Int())
			},
		},
		{
			name: "single pointer to value",
			setup: func() (reflect.Value, reflect.Value) {
				v := 42
				p := &v
				return reflect.ValueOf(p), reflect.ValueOf(p)
			},
			wantKind: reflect.Int,
			assert: func(t *testing.T, out, _ reflect.Value) {
				assert.Equal(t, int64(42), out.Int())
			},
		},
		{
			name: "double pointer to value",
			setup: func() (reflect.Value, reflect.Value) {
				v := 42
				p1 := &v
				p2 := &p1
				return reflect.ValueOf(p2), reflect.ValueOf(p2)
			},
			wantKind: reflect.Int,
			assert: func(t *testing.T, out, _ reflect.Value) {
				assert.Equal(t, int64(42), out.Int())
			},
		},
		{
			name: "allocates nil single pointer",
			setup: func() (reflect.Value, reflect.Value) {
				var p *int
				rvp := reflect.ValueOf(&p)
				return rvp.Elem(), rvp
			},
			wantKind: reflect.Int,
			assert: func(t *testing.T, out, root reflect.Value) {
				p := root.Elem().Interface().(*int)
				assert.NotNil(t, p)
				assert.Equal(t, 0, *p)
				assert.Equal(t, int64(0), out.Int())
			},
		},
		{
			name: "allocates nil double pointer",
			setup: func() (reflect.Value, reflect.Value) {
				var p **int
				rv := reflect.ValueOf(&p)
				return rv.Elem(), rv
			},
			wantKind: reflect.Int,
			assert: func(t *testing.T, out, root reflect.Value) {
				p := root.Elem().Interface().(**int)
				require.NotNil(t, p)
				require.NotNil(t, *p)
				assert.Equal(t, 0, **p)
				assert.Equal(t, int64(0), out.Int())
			},
		},
		{
			name: "stops at un-settable nil pointer",
			setup: func() (reflect.Value, reflect.Value) {
				fb := &foobar{}
				rv := reflect.ValueOf(fb).Elem().FieldByName("v")
				return rv, reflect.ValueOf(fb)
			},
			wantKind: reflect.Pointer,
			assert: func(t *testing.T, out, root reflect.Value) {
				fb := root.Interface().(*foobar)
				assert.Nil(t, fb.v)
				assert.True(t, out.IsNil(), "output should be the nil")
			},
		},
		{
			name: "allocates settable nil pointer in struct",
			setup: func() (reflect.Value, reflect.Value) {
				fb := &foobar{}
				rv := reflect.ValueOf(fb).Elem().FieldByName("V")
				return rv, reflect.ValueOf(fb)
			},
			wantKind: reflect.Int,
			assert: func(t *testing.T, out, root reflect.Value) {
				fb := root.Interface().(*foobar)
				require.NotNil(t, fb.V)
				assert.Equal(t, 0, *fb.V)
				assert.Equal(t, int64(0), out.Int())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in, root := tc.setup()
			out := pointer.Deref(in)

			assert.Equal(t, tc.wantKind, out.Kind(), "output kind mismatch")
			if tc.assert != nil {
				tc.assert(t, out, root)
			}
		})
	}
}
