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
	"fmt"
	"sync/atomic"

	"github.com/deep-rent/nexus/std/ascii"
)

// Level indicates the severity of a log record. Severity decreases with
// increasing numeric value: [LevelError] is the most severe, [LevelDebug]
// the least. The zero value is [LevelSilent], which disables logging
// entirely, so an unconfigured threshold stays quiet.
//
// The level set is fixed. There is deliberately no fatal or panic level;
// see the package documentation.
type Level byte

const (
	// LevelSilent disables all output. It is a threshold, not a loggable
	// level: it may be used to configure a sink, but records logged at this
	// level are discarded.
	LevelSilent Level = iota
	// LevelError marks failures that require attention.
	LevelError
	// LevelWarn marks anomalies that do not prevent normal operation.
	LevelWarn
	// LevelInfo marks noteworthy state changes during normal operation.
	LevelInfo
	// LevelDebug marks details useful only for troubleshooting.
	LevelDebug
)

// String returns the lower-case name of the level. Values outside the
// defined range are reported as "silent".
func (l Level) String() string {
	switch l {
	case LevelError:
		return "error"
	case LevelWarn:
		return "warn"
	case LevelInfo:
		return "info"
	case LevelDebug:
		return "debug"
	default:
		return "silent"
	}
}

// AppendText implements [encoding.TextAppender]. It appends the name of
// the level to b without allocating.
func (l Level) AppendText(b []byte) ([]byte, error) {
	if l > LevelDebug {
		return b, fmt.Errorf("invalid log level %d", byte(l))
	}
	return append(b, l.String()...), nil
}

// MarshalText implements [encoding.TextMarshaler].
func (l Level) MarshalText() ([]byte, error) {
	return l.AppendText(nil)
}

// UnmarshalText implements [encoding.TextUnmarshaler]. Level names are
// matched case-insensitively.
func (l *Level) UnmarshalText(text []byte) error {
	switch ascii.ToLower(string(text)) {
	case "silent":
		*l = LevelSilent
	case "error":
		*l = LevelError
	case "warn":
		*l = LevelWarn
	case "info":
		*l = LevelInfo
	case "debug":
		*l = LevelDebug
	default:
		return fmt.Errorf("invalid log level %q", text)
	}
	return nil
}

// ParseLevel converts a case-insensitive string into a [Level]. Valid
// inputs are "silent", "error", "warn", "info", and "debug". It returns an
// error for any other value.
func ParseLevel(s string) (level Level, err error) {
	err = level.UnmarshalText([]byte(s))
	return level, err
}

// Cutoff is an atomically adjustable level threshold. Sharing one Cutoff
// between several sinks lets a single control point, such as a SIGHUP
// handler or an admin endpoint, retune all of them at runtime.
//
// The zero value cuts off everything ([LevelSilent]). A Cutoff must not be
// copied after first use.
type Cutoff struct{ v atomic.Uint32 }

// NewCutoff creates a [Cutoff] starting at the given level.
func NewCutoff(level Level) *Cutoff {
	c := new(Cutoff)
	c.Set(level)
	return c
}

// Level returns the current threshold.
func (c *Cutoff) Level() Level {
	return Level(c.v.Load())
}

// Set atomically replaces the threshold. Values beyond [LevelDebug] are
// clamped to it.
func (c *Cutoff) Set(level Level) {
	c.v.Store(uint32(min(level, LevelDebug)))
}
