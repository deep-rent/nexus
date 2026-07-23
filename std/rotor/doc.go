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

// Package rotor provides a thread-safe, generic type for rotating through a
// slice of items according to a configurable strategy.
//
// This package is intended for load-balancing scenarios, such as selecting
// backends, rotating API keys, or distributing tasks across a pool of workers.
// The implementation is designed to ensure high performance under concurrent
// access without the need for heavy-weight mutexes.
//
// # Usage
//
// Initialize a [Rotor] with a strategy and a slice of items, then call
// [Rotor.Next] to retrieve an element.
//
// Example: Sequential rotation
//
//	backends := []string{"srv-1", "srv-2", "srv-3"}
//	r := rotor.New(rotor.Sequential, backends)
//
//	// Each call returns the next item in the sequence, wrapping around
//	// at the end.
//	s1 := r.Next() // "srv-1"
//	s2 := r.Next() // "srv-2"
//
// Example: Random selection
//
//	keys := []string{"key-1", "key-2", "key-3"}
//	r := rotor.New(rotor.Random, keys)
//
//	// Each call returns a randomly selected item.
//	k := r.Next() // e.g. "key-3"
package rotor
