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

// Package xxh3 provides a high-performance Go implementation of the 64-bit
// xxHash3 (XXH3) non-cryptographic hash algorithm designed by Yann Collet.
//
// xxHash3 is engineered for extremely high processing speed on modern CPUs,
// achieving throughput exceeding 19 GB/s by exploiting instruction-level
// parallelism, vector-friendly 64-byte stripe folding, fast 32x32-to-64 bit
// multiplications, and 128-bit fold mixes.
//
// # Key Features
//
//   - Zero Heap Allocations: All one-shot hash functions run with zero heap
//     allocations for both byte slice and string inputs.
//   - Flexible Keying Options: Supports unseeded hashing with standard keys,
//     64-bit seeded hashing, and custom secret key buffers (>= 136 bytes).
//   - Streaming Hasher: Full implementation of [hash.Hash64], [hash.Hash],
//     [io.Writer], and [io.StringWriter].
//   - State Serialization: Streaming hashers support [encoding.BinaryMarshaler]
//     and [encoding.BinaryUnmarshaler] for state persistence and recovery.
//
// # Usage Examples
//
// One-shot hashing of byte slices:
//
//	h := xxh3.Hash([]byte("hello world"))
//	hSeed := xxh3.HashSeed([]byte("hello world"), 0x12345678)
//
// One-shot hashing of strings without string-to-byte copy allocations:
//
//	hStr := xxh3.HashString("hello world")
//
// Incremental streaming hashing:
//
//	hasher := xxh3.New()
//	hasher.Write(chunk1)
//	hasher.Write(chunk2)
//	digest := hasher.Sum64()
package xxh3
