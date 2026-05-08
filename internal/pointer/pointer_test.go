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
)

func TestAlloc(t *testing.T) {
	t.Parallel()

	t.Run("allocates settable nil pointer", func(t *testing.T) {
		t.Parallel()
		var i *int
		rv := reflect.ValueOf(&i).Elem()

		if !rv.IsNil() {
			t.Fatal("precondition: pointer should be nil")
		}
		if !rv.CanSet() {
			t.Fatal("precondition: pointer should be settable")
		}

		pointer.Alloc(rv)
		if i == nil {
			t.Errorf("pointer should now point to a value")
		} else if got, want := *i, 0; got != want {
			t.Errorf("*i = %d; want %d", got, want)
		}
	})

	t.Run("panics on non-settable pointer", func(t *testing.T) {
		t.Parallel()
		type foobar struct{ v *int } //nolint:unused
		rv := reflect.ValueOf(foobar{}).FieldByName("v")
		if rv.CanSet() {
			t.Fatal("precondition: value should not be settable")
		}

		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Alloc did not panic on non-settable pointer")
			}
		}()
		pointer.Alloc(rv)
	})
}

func TestDeref(t *testing.T) {
	t.Parallel()

	type foobar struct {
		V *int
		v *int
	}

	tests := []struct {
		name     string
		setup    func() (in, root reflect.Value)
		wantKind reflect.Kind
		check    func(t *testing.T, out, root reflect.Value)
	}{
		{
			name: "non-pointer value",
			setup: func() (reflect.Value, reflect.Value) {
				v := 42
				return reflect.ValueOf(v), reflect.ValueOf(v)
			},
			wantKind: reflect.Int,
			check: func(t *testing.T, out, _ reflect.Value) {
				if got, want := out.Int(), int64(42); got != want {
					t.Errorf("out.Int() = %d; want %d", got, want)
				}
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
			check: func(t *testing.T, out, _ reflect.Value) {
				if got, want := out.Int(), int64(42); got != want {
					t.Errorf("out.Int() = %d; want %d", got, want)
				}
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
			check: func(t *testing.T, out, _ reflect.Value) {
				if got, want := out.Int(), int64(42); got != want {
					t.Errorf("out.Int() = %d; want %d", got, want)
				}
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
			check: func(t *testing.T, out, root reflect.Value) {
				p := root.Elem().Interface().(*int)
				if p == nil {
					t.Errorf("root pointer should not be nil")
				} else if got, want := *p, 0; got != want {
					t.Errorf("*p = %d; want %d", got, want)
				}
				if got, want := out.Int(), int64(0); got != want {
					t.Errorf("out.Int() = %d; want %d", got, want)
				}
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
			check: func(t *testing.T, out, root reflect.Value) {
				p := root.Elem().Interface().(**int)
				if p == nil || *p == nil {
					t.Fatalf("pointers were not allocated")
				}
				if got, want := **p, 0; got != want {
					t.Errorf("**p = %d; want %d", got, want)
				}
				if got, want := out.Int(), int64(0); got != want {
					t.Errorf("out.Int() = %d; want %d", got, want)
				}
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
			check: func(t *testing.T, out, root reflect.Value) {
				fb := root.Interface().(*foobar)
				if fb.v != nil {
					t.Errorf("fb.v should remain nil")
				}
				if !out.IsNil() {
					t.Errorf("output should be nil")
				}
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
			check: func(t *testing.T, out, root reflect.Value) {
				fb := root.Interface().(*foobar)
				if fb.V == nil {
					t.Fatalf("fb.V was not allocated")
				}
				if got, want := *fb.V, 0; got != want {
					t.Errorf("*fb.V = %d; want %d", got, want)
				}
				if got, want := out.Int(), int64(0); got != want {
					t.Errorf("out.Int() = %d; want %d", got, want)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in, root := tt.setup()
			out := pointer.Deref(in)

			if got, want := out.Kind(), tt.wantKind; got != want {
				t.Errorf("Deref().Kind() = %v; want %v", got, want)
			}
			if tt.check != nil {
				tt.check(t, out, root)
			}
		})
	}
}
