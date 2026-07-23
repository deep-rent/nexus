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

// Package flush provides a concurrency-safe, buffered [io.Writer] that
// amortizes write system calls for high-frequency writers, such as
// structured loggers emitting one line per record.
//
// A [Writer] accumulates writes in memory and forwards them to the
// underlying destination when the buffer fills, when a flush interval
// elapses, or when [Writer.Flush] or [Writer.Close] is called. Batching
// this way turns thousands of small syscalls per second into a few large
// ones, at the price of a bounded loss window: output produced since the
// last flush is lost if the process dies without closing the writer.
// Deployments that cannot afford to lose a single record should write
// unbuffered instead.
//
// # Usage
//
// Wrap the destination and hand the writer to the producer; close it on
// shutdown to drain the tail:
//
//	w := flush.New(os.Stdout)
//	defer w.Close()
//
//	logger := log.New(log.WithWriter(w))
//
// The flush cadence and buffer capacity are configurable:
//
//	w := flush.New(f,
//		flush.WithSize(256<<10),
//		flush.WithInterval(5*time.Second),
//	)
//
// A [Writer] serializes access internally, so the destination need not be
// safe for concurrent use. Byte streams pass through unaltered, but a
// single write may be split across multiple writes to the destination
// when it straddles the buffer boundary; wrap only stream-oriented
// destinations such as files, pipes, and sockets.
package flush
