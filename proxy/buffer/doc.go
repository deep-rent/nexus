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

// Package buffer provides a sync.Pool-backed implementation of
// [httputil.BufferPool] for reusing byte slices.
//
// It is designed to save memory and reduce GC pressure when dealing with large
// response bodies by recycling memory buffers. This implementation helps
// stabilize heap usage in high-throughput proxies or servers that frequently
// allocate temporary buffers for I/O operations.
//
// # Usage
//
// Create a new [Pool] and pass it to a reverse proxy or any component requiring
// a [httputil.BufferPool].
//
// Example:
//
//	// Create a pool with 32KB initial buffers, capped at 1MB for reuse.
//	pool := buffer.NewPool(32*1024, 1024*1024)
//
//	proxy := &httputil.ReverseProxy{
//		Director:   director,
//		BufferPool: pool,
//	}
package buffer
