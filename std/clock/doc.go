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

// Package clock provides an injectable time source.
//
// [Clock] is a function type compatible with [time.Now], so production code
// can default to [System] while tests supply a deterministic replacement
// without threading a bespoke func() time.Time through every call site.
//
// # Usage
//
// Store a [Clock] wherever the current time is needed and default it to
// [System]:
//
//	type Server struct {
//		clock clock.Clock
//	}
//
//	func New() *Server {
//		return &Server{clock: clock.System}
//	}
//
// Tests replace the field with a fixed instant so temporal logic becomes
// reproducible:
//
//	s.clock = clock.Frozen(time.Unix(0, 0))
//
// [Frozen] and [Clock.Offset] compose to simulate clock skew without waiting
// for wall-clock time to pass.
package clock
