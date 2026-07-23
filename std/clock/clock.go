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

package clock

import "time"

// Clock reports the current time. Being a function type, it is assignable
// from [time.Now] and any other source of the same shape, which lets callers
// swap the real-time clock for a deterministic one in tests.
type Clock func() time.Time

// Now returns the current time as reported by the clock.
func (c Clock) Now() time.Time {
	return c()
}

// Since returns the time elapsed since the given instant. It is shorthand for
// c.Now().Sub(t).
func (c Clock) Since(t time.Time) time.Duration {
	return c().Sub(t)
}

// Until returns the duration until the given instant. It is shorthand for
// t.Sub(c.Now()).
func (c Clock) Until(t time.Time) time.Duration {
	return t.Sub(c())
}

// Offset returns a clock that reports the time of c shifted by the given
// duration. A positive duration runs the clock ahead, a negative one behind,
// which is useful for simulating clock skew.
func (c Clock) Offset(d time.Duration) Clock {
	return func() time.Time { return c().Add(d) }
}

// System is the real-time clock backed by [time.Now]. It is the default for
// production use.
var System Clock = time.Now

// Frozen returns a clock that always reports the given instant, regardless of
// how much wall-clock time passes.
func Frozen(at time.Time) Clock {
	return func() time.Time { return at }
}
