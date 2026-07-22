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

package xxh3

import (
	"testing"
)

// BenchmarkHash8B measures 64-bit xxHash3 throughput for small 8-byte
// payloads.
func BenchmarkHash8B(b *testing.B) {
	data := []byte("12345678")
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()

	for b.Loop() {
		_ = Hash(data)
	}
}

// BenchmarkHash64B measures 64-bit xxHash3 throughput for single 64-byte
// stripe payloads.
func BenchmarkHash64B(b *testing.B) {
	data := make([]byte, 64)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()

	for b.Loop() {
		_ = Hash(data)
	}
}

// BenchmarkHash1KB measures 64-bit xxHash3 throughput for 1 KB payloads
// spanning a full 1024-byte block.
func BenchmarkHash1KB(b *testing.B) {
	data := make([]byte, 1024)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()

	for b.Loop() {
		_ = Hash(data)
	}
}

// BenchmarkHash64KB measures 64-bit xxHash3 throughput for large 64 KB
// stream buffers.
func BenchmarkHash64KB(b *testing.B) {
	data := make([]byte, 65536)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()

	for b.Loop() {
		_ = Hash(data)
	}
}
