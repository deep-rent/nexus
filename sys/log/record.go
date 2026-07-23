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

import "time"

// Record is a single log entry as handed to a [Sink].
type Record struct {
	// Time is the instant at which the record was created. Sinks normalize
	// it to UTC on output.
	Time time.Time
	// Level is the severity of the record.
	Level Level
	// Logger is the dotted path of the emitting logger, such as
	// "http.server". It is empty for the root logger.
	Logger string
	// Msg is the log message.
	Msg string
	// Args holds the arguments passed at the call site. The slice is only
	// valid for the duration of [Sink.Receive]; a sink that retains
	// arguments beyond that call must copy them.
	Args []Arg
}
