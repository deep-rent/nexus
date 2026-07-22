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

// Package bind provides a reflective struct binding engine for populating
// struct fields from arbitrary key-value data sources.
//
// It serves as the core binding mechanism for configuration packages like env
// and HTTP routing layers. It parses struct tags, supports configurable field
// name transformations, handles primitive and standard library type conversions
// (such as [time.Duration] and [url.URL]), and supports optional reflection
// metadata caching for optimal performance.
//
// # Usage
//
// Create a Binder targeting a specific struct tag namespace and populate target
// structs using a custom or built-in Source implementation.
//
// Example:
//
//	binder := bind.New("form", bind.WithCache(true))
//	err := binder.Bind(&myStruct, "", mySource)
package bind
