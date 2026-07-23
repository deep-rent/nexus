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
	"math"
	"time"
	"unsafe"
	"uuid"
)

// Kind identifies the type of value carried by an [Arg].
type Kind uint8

const (
	// KindString marks a string value.
	KindString Kind = iota
	// KindInt64 marks a signed integer value.
	KindInt64
	// KindUint64 marks an unsigned integer value.
	KindUint64
	// KindFloat64 marks a 64-bit floating-point value.
	KindFloat64
	// KindFloat32 marks a 32-bit floating-point value. It is distinct
	// from [KindFloat64] so that values keep their 32-bit precision on
	// output instead of picking up conversion noise.
	KindFloat32
	// KindBool marks a boolean value.
	KindBool
	// KindDuration marks a [time.Duration] value.
	KindDuration
	// KindTime marks a [time.Time] value.
	KindTime
	// KindError marks an error value.
	KindError
)

// Arg is a typed key/value pair attached to a log record. Args are plain
// values constructed with functions like [String], [Int], or [Error];
// building one does not allocate for any kind except [Time] values that
// fall outside the range representable as Unix nanoseconds.
//
// The set of kinds is fixed. There is deliberately no constructor for
// arbitrary values: every value passes through a typed constructor, which
// keeps sinks free of reflection. Callers with a complex value serialize
// it themselves and log the result as a [String].
//
// Args are not comparable with ==, since string values are packed as
// pointer and length; compare keys, kinds, and [Arg.Value] instead.
type Arg struct {
	_ [0]func() // disallow ==

	// Key names the argument in the log record.
	Key string

	kind Kind
	num  uint64
	any  any
}

// stringptr marks the packed data pointer of a string value held in
// Arg.any. Being pointer-shaped, it enters the interface without
// allocating.
type stringptr *byte

// str unpacks the string carried by a [KindString] argument.
func (a Arg) str() string {
	if p, ok := a.any.(stringptr); ok {
		return unsafe.String(p, int(a.num))
	}
	return ""
}

// Kind returns the kind of the value carried by the argument.
func (a Arg) Kind() Kind {
	return a.kind
}

// Value returns the carried value boxed as any: a string, int64, uint64,
// float64, float32, bool, [time.Duration], [time.Time], or error,
// depending on the kind. Value is meant for tests and custom sinks; the
// built-in JSON sink never boxes.
func (a Arg) Value() any {
	switch a.kind {
	case KindString:
		return a.str()
	case KindInt64:
		return int64(a.num)
	case KindUint64:
		return a.num
	case KindFloat64:
		return math.Float64frombits(a.num)
	case KindFloat32:
		return math.Float32frombits(uint32(a.num))
	case KindBool:
		return a.num != 0
	case KindDuration:
		return time.Duration(a.num)
	case KindTime:
		return a.time()
	case KindError:
		if a.any == nil {
			return nil
		}
		return a.any
	default:
		return nil
	}
}

// String returns an [Arg] carrying a string value. The value is packed
// as data pointer and length, so no allocation or copy takes place.
func String(key, val string) Arg {
	return Arg{
		Key:  key,
		kind: KindString,
		num:  uint64(len(val)),
		any:  stringptr(unsafe.StringData(val)),
	}
}

// Int returns an [Arg] carrying an int value as an int64.
func Int(key string, val int) Arg {
	return Int64(key, int64(val))
}

// Int8 returns an [Arg] carrying an int8 value as an int64.
func Int8(key string, val int8) Arg {
	return Int64(key, int64(val))
}

// Int16 returns an [Arg] carrying an int16 value as an int64.
func Int16(key string, val int16) Arg {
	return Int64(key, int64(val))
}

// Int32 returns an [Arg] carrying an int32 value as an int64.
func Int32(key string, val int32) Arg {
	return Int64(key, int64(val))
}

// Int64 returns an [Arg] carrying an int64 value.
func Int64(key string, val int64) Arg {
	return Arg{Key: key, kind: KindInt64, num: uint64(val)}
}

// Uint returns an [Arg] carrying a uint value as a uint64.
func Uint(key string, val uint) Arg {
	return Uint64(key, uint64(val))
}

// Uint8 returns an [Arg] carrying a uint8 value as a uint64.
func Uint8(key string, val uint8) Arg {
	return Uint64(key, uint64(val))
}

// Uint16 returns an [Arg] carrying a uint16 value as a uint64.
func Uint16(key string, val uint16) Arg {
	return Uint64(key, uint64(val))
}

// Uint32 returns an [Arg] carrying a uint32 value as a uint64.
func Uint32(key string, val uint32) Arg {
	return Uint64(key, uint64(val))
}

// Uint64 returns an [Arg] carrying a uint64 value.
func Uint64(key string, val uint64) Arg {
	return Arg{Key: key, kind: KindUint64, num: val}
}

// Float32 returns an [Arg] carrying a float32 value. Unlike a conversion
// through [Float64], the value is encoded at 32-bit precision, so its
// shortest decimal representation is preserved.
func Float32(key string, val float32) Arg {
	return Arg{Key: key, kind: KindFloat32, num: uint64(math.Float32bits(val))}
}

// Float64 returns an [Arg] carrying a float64 value.
func Float64(key string, val float64) Arg {
	return Arg{Key: key, kind: KindFloat64, num: math.Float64bits(val)}
}

// Bool returns an [Arg] carrying a bool value.
func Bool(key string, val bool) Arg {
	var n uint64
	if val {
		n = 1
	}
	return Arg{Key: key, kind: KindBool, num: n}
}

// Duration returns an [Arg] carrying a [time.Duration] value. The JSON
// sink encodes durations as seconds, matching the convention used for
// metrics throughout this codebase.
func Duration(key string, val time.Duration) Arg {
	return Arg{Key: key, kind: KindDuration, num: uint64(val)}
}

// Time returns an [Arg] carrying a [time.Time] value. The JSON sink
// encodes times in UTC using [time.RFC3339Nano]; the location of val does
// not survive, only the instant.
func Time(key string, val time.Time) Arg {
	// The instant is stored as Unix nanoseconds to avoid boxing; times
	// outside the representable range fall back to the interface field.
	if y := val.Year(); y >= 1679 && y <= 2261 {
		return Arg{Key: key, kind: KindTime, num: uint64(val.UnixNano())}
	}
	return Arg{Key: key, kind: KindTime, any: val}
}

// time reconstructs the instant carried by a [KindTime] argument.
func (a Arg) time() time.Time {
	if t, ok := a.any.(time.Time); ok {
		return t
	}
	return time.Unix(0, int64(a.num)).UTC()
}

// UUID returns an [Arg] carrying the canonical textual form of a
// [uuid.UUID] as a string value.
func UUID(key string, id uuid.UUID) Arg {
	return String(key, id.String())
}

// ErrorKey is the key under which [Error] records an error. It is exported
// so that sinks and log processors can find errors by a stable name.
const ErrorKey = "error"

// Error returns an [Arg] carrying err under the [ErrorKey]. It is the
// canonical way to log an error in this codebase, so that every error is
// recorded under the same key and enriching that record later is a change
// in one place rather than at every call site:
//
//	logger.Error(ctx, "Failed to fetch resource", log.Error(err))
//
// A nil error is encoded as null; callers should log an error argument
// only when there is an error to report.
//
// If the error, or any error in its chain, is [Traceable], the JSON sink
// also records its occurrence identifier under [ErrorIDKey].
func Error(err error) Arg {
	return Arg{Key: ErrorKey, kind: KindError, any: err}
}

// ErrorIDKey is the key under which the JSON sink records the identifier
// of a [Traceable] error. It is exported so that sinks and log processors
// can find error identifiers by a stable name.
const ErrorIDKey = "error_id"

// Traceable is the interface of errors that carry a unique identifier
// for their specific occurrence, correlating client-side reports with
// server-side logs. When an error logged via [Error] has a Traceable in
// its chain, the JSON sink automatically records the identifier under
// [ErrorIDKey], so call sites never attach it by hand.
type Traceable interface {
	error

	// ErrorID returns the unique identifier of this error occurrence.
	// An empty identifier is not recorded.
	ErrorID() string
}

// errorID extracts the occurrence identifier of the first [Traceable] in
// the chain of err, traversing wrapped and joined errors like
// [errors.As]. It unwraps manually, since errors.As forces its target
// onto the heap and resolves matches through reflection; plain type
// assertions keep the probe free of both.
func errorID(err error) string {
	for err != nil {
		if t, ok := err.(Traceable); ok {
			return t.ErrorID()
		}
		switch x := err.(type) {
		case interface{ Unwrap() error }:
			err = x.Unwrap()
		case interface{ Unwrap() []error }:
			for _, e := range x.Unwrap() {
				if id := errorID(e); id != "" {
					return id
				}
			}
			return ""
		default:
			return ""
		}
	}
	return ""
}
