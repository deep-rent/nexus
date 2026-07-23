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

package log_test

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/deep-rent/nexus/std/flush"
	"github.com/deep-rent/nexus/sys/log"
)

func BenchmarkLog(b *testing.B) {
	logger := log.New(log.WithWriter(io.Discard))
	ctx := b.Context()
	err := errors.New("boom")

	b.ReportAllocs()
	for b.Loop() {
		logger.Info(ctx, "Request handled",
			log.String("method", "GET"),
			log.String("path", "/api/v1/units"),
			log.Int("status", 200),
			log.Duration("elapsed", 1500*time.Microsecond),
			log.Error(err),
		)
	}
}

func BenchmarkLog_Bound(b *testing.B) {
	logger := log.New(log.WithWriter(io.Discard)).With(
		log.String("app", "api"),
		log.String("request_id", "0195c2a7-9e4b-7c58"),
		log.Int("shard", 3),
	)
	ctx := b.Context()

	b.ReportAllocs()
	for b.Loop() {
		logger.Info(ctx, "Request handled", log.Int("status", 200))
	}
}

func BenchmarkLog_Disabled(b *testing.B) {
	logger := log.New(log.WithWriter(io.Discard))
	ctx := b.Context()

	b.ReportAllocs()
	for b.Loop() {
		logger.Debug(ctx, "Request handled",
			log.String("method", "GET"),
			log.Int("status", 200),
		)
	}
}

// The syscall pair below measures the write path against a real file
// descriptor: one write(2) per record versus batches amortized through a
// flush.Writer.

func BenchmarkLog_Syscall(b *testing.B) {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		b.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer f.Close()

	logger := log.New(log.WithWriter(f))
	ctx := b.Context()

	b.ReportAllocs()
	for b.Loop() {
		logger.Info(ctx, "Request handled", log.Int("status", 200))
	}
}

func BenchmarkLog_SyscallFlushed(b *testing.B) {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		b.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer f.Close()

	w := flush.New(f)
	defer w.Close()

	logger := log.New(log.WithWriter(w))
	ctx := b.Context()

	b.ReportAllocs()
	for b.Loop() {
		logger.Info(ctx, "Request handled", log.Int("status", 200))
	}
}

func BenchmarkLog_DisabledGuarded(b *testing.B) {
	logger := log.New(log.WithWriter(io.Discard))
	ctx := b.Context()

	b.ReportAllocs()
	for b.Loop() {
		if logger.Enabled(ctx, log.LevelDebug) {
			logger.Debug(ctx, "Request handled",
				log.String("method", "GET"),
				log.Int("status", 200),
			)
		}
	}
}
