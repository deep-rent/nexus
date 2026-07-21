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
//
// These functions are useful for dynamically allocating and dereferencing
// variables in contexts like configuration loading or data mapping. By using
// the [reflect] package, this package allows for the manipulation of types
// where the concrete structure is not known at compile time.
//
// # Usage
//
// The primary helpers allow for safe allocation and deep dereferencing of
// [reflect.Value] types.
//
// Example:
//
//	var str *string
//	rv := reflect.ValueOf(&str).Elem()
//
//	// Allocates a new string and sets the pointer
//	pointer.Alloc(rv)
//
//	// Deeply dereferences even nested pointers like **int
//	final := pointer.Deref(rv)
package pointer
