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

// Package pointer provides reflection-based helpers for working with pointers.
// These functions are useful for dynamically allocating and dereferencing
// variables in contexts like configuration loading or data mapping.
package pointer

import "reflect"

// Alloc allocates a new value for a nil pointer and sets the pointer to it.
//
// This function causes a panic if rv is not a settable pointer.
func Alloc(rv reflect.Value) {
	rv.Set(reflect.New(rv.Type().Elem()))
}

// Deref follows pointers until it reaches a non-pointer, allocating if nil.
//
// If a nil pointer is encountered along the way, Deref will attempt to allocate
// a new value for it. If it encounters an un-settable nil pointer (e.g., one
// within an unexported struct field), it stops and returns that pointer to
// prevent a panic. The final, non-pointer value is returned.
func Deref(rv reflect.Value) reflect.Value {
	// Loop through multi-level pointers to handle cases like **int.
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			// If the pointer is nil but cannot be set, we must stop
			// here to avoid a panic.
			if !rv.CanSet() {
				break
			}
			Alloc(rv)
		}
		rv = rv.Elem()
	}
	return rv
}
