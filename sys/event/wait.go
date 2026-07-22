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

package event

import (
	"runtime"
	"time"
)

// WaitStrategy defines the idling behavior of the background processor when the
// ring buffer is empty.
type WaitStrategy interface {
	// Snooze is called when the buffer is empty. The idle parameter represents
	// the number of consecutive empty polls.
	Snooze(idle int)
	// Signal awakens the processor from a Snooze when a new event arrives.
	Signal()
}

// adaptiveWait employs a spin-yield-sleep sequence to minimize latency while
// preventing constant CPU burn during idle periods.
type adaptiveWait struct{}

// Snooze scales the waiting mechanism based on how long the bus has been idle.
func (adaptiveWait) Snooze(idle int) {
	const (
		phase1 = 1000 // Spin-yield limit
		phase2 = 5000 // Sleep limit
	)

	switch {
	case idle < phase1:
		// Low latency mode: Yield the processor but stay actively scheduled.
		runtime.Gosched()
	case idle < phase2:
		// Cooldown mode: Drop CPU usage significantly while maintaining fast
		// response.
		time.Sleep(time.Microsecond)
	default:
		// Deep idle mode: Near 0% CPU consumption.
		time.Sleep(time.Millisecond)
	}
}

// Signal is a no-op because the loop actively wakes itself up.
func (adaptiveWait) Signal() {}

// blockingWait uses a semaphore channel to park the goroutine entirely when
// idle, saving CPU cycles at the cost of a slight wakeup latency.
type blockingWait struct {
	// sem is a buffered channel acting as a non-blocking signaling mechanism.
	sem chan struct{}
}

// Snooze parks the goroutine until a value is received on the semaphore
// channel.
func (w *blockingWait) Snooze(_ int) { <-w.sem }

// Signal attempts to send a wakeup token. If the channel already has a token,
// it drops the send to avoid blocking the publisher.
func (w *blockingWait) Signal() {
	select {
	case w.sem <- struct{}{}:
	default:
	}
}
