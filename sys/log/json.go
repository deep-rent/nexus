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

package log

import (
	"context"
	"io"
	"math"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/deep-rent/nexus/std/ascii"
)

// NewSink creates and configures the JSON [Sink]. By default, it logs at
// [DefaultLevel] to [os.Stdout]. These defaults can be overridden by
// passing in one or more [Option] functions.
//
// The sink appends one JSON object per record, terminated by a newline,
// in a single write. Timestamps are normalized to UTC and formatted as
// [time.RFC3339Nano]; there are no other formats. Encoding is
// reflection-free: each record is assembled in a pooled buffer, and
// arguments bound via [Sink.With] are pre-encoded once.
func NewSink(opts ...Option) Sink {
	c := config{
		level:  DefaultLevel,
		writer: os.Stdout,
	}
	for _, opt := range opts {
		opt(&c)
	}

	cutoff := c.cutoff
	if cutoff == nil {
		cutoff = NewCutoff(c.level)
	}

	var redact map[string]struct{}
	if len(c.redact) > 0 {
		redact = make(map[string]struct{}, len(c.redact))
		for _, k := range c.redact {
			redact[ascii.ToLower(k)] = struct{}{}
		}
	}

	return &sink{
		out:    c.writer,
		mu:     new(sync.Mutex),
		cutoff: cutoff,
		redact: redact,
		derive: c.derive,
	}
}

// sink implements the JSON [Sink] returned by [NewSink].
type sink struct {
	// out is the output destination.
	out io.Writer
	// mu serializes writes to out. It is a pointer so that all sinks
	// derived via With share it.
	mu *sync.Mutex
	// cutoff is the level threshold, possibly shared.
	cutoff *Cutoff
	// redact holds lower-cased keys whose values are masked.
	redact map[string]struct{}
	// derive derives ambient arguments from the record context.
	derive func(ctx context.Context, args []Arg) []Arg
	// prefix holds the arguments bound via With, pre-encoded as a raw
	// JSON fragment of the form `,"key":value,...`.
	prefix []byte
}

func (s *sink) Enabled(ctx context.Context, level Level) bool {
	if level == LevelSilent || level > LevelDebug {
		return false
	}
	cut := s.cutoff.Level()
	if override, ok := GetLevel(ctx); ok {
		cut = override
	}
	return level <= cut
}

func (s *sink) Receive(ctx context.Context, r Record) {
	bp := pool.Get().(*[]byte)
	b := (*bp)[:0]

	b = append(b, `{"time":"`...)
	b = r.Time.UTC().AppendFormat(b, time.RFC3339Nano)
	b = append(b, `","level":"`...)
	b = append(b, r.Level.String()...)
	b = append(b, '"')
	if r.Logger != "" {
		b = append(b, `,"logger":`...)
		b = appendString(b, r.Logger)
	}
	b = append(b, `,"msg":`...)
	b = appendString(b, r.Msg)
	b = append(b, s.prefix...)
	if s.derive != nil {
		var scratch [4]Arg
		for _, a := range s.derive(ctx, scratch[:0]) {
			b = s.appendArg(b, a)
		}
	}
	for _, a := range r.Args {
		b = s.appendArg(b, a)
	}
	b = append(b, '}', '\n')

	s.mu.Lock()
	_, _ = s.out.Write(b)
	s.mu.Unlock()

	// Return the buffer to the pool unless a huge record grew it; holding
	// on to such a buffer would pin its memory indefinitely.
	if cap(b) <= maxPooled {
		*bp = b
		pool.Put(bp)
	}
}

func (s *sink) With(args []Arg) Sink {
	if len(args) == 0 {
		return s
	}
	c := *s
	// Clip forces the first append to reallocate, so that sibling sinks
	// derived from the same parent never share backing memory.
	prefix := slices.Clip(s.prefix)
	for _, a := range args {
		prefix = c.appendArg(prefix, a)
	}
	c.prefix = prefix
	return &c
}

// redacted is the marker substituted for masked argument values.
const redacted = `"[REDACTED]"`

// appendArg appends an argument to b as a `,"key":value` fragment.
func (s *sink) appendArg(b []byte, a Arg) []byte {
	b = append(b, ',')
	b = appendString(b, a.Key)
	b = append(b, ':')
	if s.redact != nil {
		if _, ok := s.redact[ascii.ToLower(a.Key)]; ok {
			return append(b, redacted...)
		}
	}
	switch a.kind {
	case KindString:
		return appendString(b, a.str())
	case KindInt64:
		return strconv.AppendInt(b, int64(a.num), 10)
	case KindUint64:
		return strconv.AppendUint(b, a.num, 10)
	case KindFloat64:
		return appendFloat(b, math.Float64frombits(a.num), 64)
	case KindFloat32:
		f := math.Float32frombits(uint32(a.num))
		return appendFloat(b, float64(f), 32)
	case KindBool:
		return strconv.AppendBool(b, a.num != 0)
	case KindDuration:
		return appendFloat(b, time.Duration(a.num).Seconds(), 64)
	case KindTime:
		b = append(b, '"')
		b = a.time().UTC().AppendFormat(b, time.RFC3339Nano)
		return append(b, '"')
	case KindError:
		if a.any == nil {
			return append(b, "null"...)
		}
		err := a.any.(error)
		b = appendString(b, err.Error())
		// A traceable error also carries its occurrence identifier, so
		// one Err at the call site records both under stable keys.
		if id := errorID(err); id != "" {
			b = append(b, `,"`...)
			b = append(b, ErrorIDKey...)
			b = append(b, `":`...)
			b = appendString(b, id)
		}
		return b
	default:
		return append(b, "null"...)
	}
}

// appendFloat appends f as a JSON number using the shortest decimal
// representation for the given bit size. NaN and the infinities have no
// JSON representation and are encoded as strings instead.
func appendFloat(b []byte, f float64, bits int) []byte {
	switch {
	case math.IsNaN(f):
		return append(b, `"NaN"`...)
	case math.IsInf(f, +1):
		return append(b, `"+Inf"`...)
	case math.IsInf(f, -1):
		return append(b, `"-Inf"`...)
	default:
		return strconv.AppendFloat(b, f, 'g', -1, bits)
	}
}

// hexDigits is used to encode control characters as \u00XX escapes.
const hexDigits = "0123456789abcdef"

// appendString appends s to b as a JSON string literal. Runs of safe
// bytes are copied in bulk; control characters are escaped, and invalid
// UTF-8 is replaced by the Unicode replacement character, matching
// [encoding/json].
func appendString(b []byte, s string) []byte {
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); {
		if c := s[i]; c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' {
				i++
				continue
			}
			b = append(b, s[start:i]...)
			switch c {
			case '"':
				b = append(b, '\\', '"')
			case '\\':
				b = append(b, '\\', '\\')
			case '\n':
				b = append(b, '\\', 'n')
			case '\r':
				b = append(b, '\\', 'r')
			case '\t':
				b = append(b, '\\', 't')
			default:
				b = append(b,
					'\\', 'u', '0', '0',
					hexDigits[c>>4],
					hexDigits[c&0xF],
				)
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b = append(b, s[start:i]...)
			b = append(b, `�`...)
			i += size
			start = i
			continue
		}
		i += size
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}

// maxPooled caps the capacity of buffers returned to the pool.
const maxPooled = 16 << 10

// pool recycles record buffers across Receive calls.
var pool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1<<10)
		return &b
	},
}
