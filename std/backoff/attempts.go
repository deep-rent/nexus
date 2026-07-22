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

package backoff

import (
	"context"
	"time"
)

// Attempts is a running counter over a [Strategy], scoped to a single retried
// operation.
//
// Unlike a [Strategy], an Attempts value is stateful and therefore NOT safe
// for concurrent use. Create one per operation; sharing it between operations
// makes them inflate each other's delays and reset each other's progress.
type Attempts struct {
	s Strategy // underlying strategy supplying the delays
	n int      // number of delays handed out so far
}

// Count returns an [Attempts] counter that draws its delays from s. It panics
// if s is nil.
func Count(s Strategy) *Attempts {
	if s == nil {
		panic("count requires a non-nil strategy")
	}
	return &Attempts{s: s}
}

// Next advances the counter and returns the delay preceding the next attempt.
func (a *Attempts) Next() time.Duration {
	a.n++
	return a.s.Delay(a.n)
}

// Wait advances the counter and blocks for the resulting delay, returning
// early if ctx is canceled. See [Wait] for the error semantics.
func (a *Attempts) Wait(ctx context.Context) error {
	return Wait(ctx, a.Next())
}

// Count reports how many delays have been handed out since the counter was
// created or last reset.
func (a *Attempts) Count() int { return a.n }

// Reset returns the counter to its initial state, so that the next call to
// [Attempts.Next] yields the delay of the first retry again. It must be called
// before the counter is reused for another operation.
func (a *Attempts) Reset() { a.n = 0 }

// Wait blocks for the duration d, or until ctx is done, whichever happens
// first. It returns nil once the full duration has elapsed, and the result of
// [context.Context.Err] if the context was canceled first.
//
// A non-positive duration returns immediately, but the context is still
// checked, so a canceled context is reported even when there is no waiting to
// be done.
func Wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
