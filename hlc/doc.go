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

// Package hlc provides a Hybrid Logical Clock (HLC) implementation.
//
// HLCs are used to generate causally ordered timestamps for distributed
// systems. They combine a physical wall-clock timestamp (in Unix seconds)
// with a logical counter, fitting both into a single uint64.
//
// A timestamp packs 33 bits of physical seconds (sufficient until the year
// 2242) and 20 bits of logical counter (about one million increments per
// second) into 53 bits total. Every timestamp therefore fits losslessly
// into an IEEE 754 double, a signed 64-bit integer, and a JSON number as
// consumed by JavaScript clients.
//
// # Usage
//
// The clock provides two methods: [Now] for generating timestamps and [Update]
// for updating the clock with a remote timestamp.
//
// Example:
//
//	// Create a new clock.
//	c := hlc.New(nil)
//
//	// Generate a timestamp.
//	t := c.Now()
//
//	// Update the clock with a remote timestamp.
//	t, err := c.Update(t)
package hlc
