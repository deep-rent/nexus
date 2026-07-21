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

// Package schedule provides a flexible framework for running recurring tasks.
//
// This package manages the lifecycle of concurrent, scheduled jobs. The
// basic unit of work is a [Task], which can be adapted into a schedulable
// [Tick]. A [Tick] is a self-repeating job that determines its own next run
// time by returning a duration after each execution.
//
// # Usage
//
// Helpers like [Every] and [After] are provided to easily convert a simple
// [Task] into a [Tick] with common scheduling patterns:
//
//   - [Every]: Creates a drift-free Tick that runs at a fixed cadence,
//     accounting for the task's own execution time.
//   - [After]: Creates a drifting Tick that waits for a fixed duration after
//     the previous run completes.
//
// Example:
//
//	s := schedule.New(context.Background())
//	defer s.Shutdown()
//
//	task := schedule.TaskFn(func(context.Context) {
//	  slog.Info("Tick!")
//	})
//
//	tick := schedule.Every(2*time.Second, task)
//	s.Dispatch(tick)
//
//	// Let the scheduler run for a while.
//	time.Sleep(5 * time.Second)
package schedule
