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

// Package backoff provides customizable strategies for retrying operations
// with increasing delays.
//
// The core of the package is the [Strategy] interface, which maps an attempt
// number to the delay preceding that attempt. Strategies are stateless and
// safe for concurrent use, so a single strategy can be shared by any number of
// operations running in parallel. Callers that prefer a running counter over
// passing attempt numbers can wrap a strategy in [Attempts], which is scoped
// to one operation.
//
// # Usage
//
// A default exponential strategy with jitter is created using [New]. Its
// behavior is customized with [Option] functions such as [WithMinDelay],
// [WithMaxDelay], [WithGrowthFactor], and [WithJitterAmount]. Jitter is
// applied by default to prevent multiple clients from retrying in sync (the
// "thundering herd" problem), which can overwhelm a recovering service.
//
// Example:
//
//	s := backoff.New(
//		backoff.WithMinDelay(500*time.Millisecond),
//		backoff.WithMaxDelay(30*time.Second),
//	)
//
//	for n := 1; ; n++ {
//		err := doWork()
//		if err == nil {
//			break
//		}
//		if err := backoff.Wait(ctx, s.Delay(n)); err != nil {
//			return err // The context was canceled.
//		}
//	}
//
// The same loop written with a counter:
//
//	a := backoff.Count(s)
//	for {
//		err := doWork()
//		if err == nil {
//			break
//		}
//		if err := a.Wait(ctx); err != nil {
//			return err
//		}
//	}
package backoff
