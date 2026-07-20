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

package event_test

import (
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deep-rent/nexus/event"
)

// A closed broker owns no buses, so it must not start processors that nothing
// will ever stop.
func TestBroker_TopicAfterCloseDoesNotLeak(t *testing.T) {
	t.Parallel()

	b := event.NewBroker()
	b.Close()

	// Settle whatever the runtime was already doing.
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	const topics = 20
	for i := range topics {
		bus := event.Topic[int](b, strconv.Itoa(i))

		if bus.Publish(1) {
			t.Error("publish on a closed broker: got true; want false")
		}
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	if after := runtime.NumGoroutine(); after-before >= topics {
		t.Errorf("goroutines: got %d; want close to %d", after, before)
	}
}

func TestBroker_TopicReuse(t *testing.T) {
	t.Parallel()

	b := event.NewBroker(event.WithSyncDispatch())
	defer b.Close()

	first := event.Topic[int](b, "numbers")
	second := event.Topic[int](b, "numbers")

	if first != second {
		t.Error("got distinct buses; want the same one for a repeated topic")
	}
}

func TestBroker_TopicTypeMismatch(t *testing.T) {
	t.Parallel()

	b := event.NewBroker()
	defer b.Close()

	event.Topic[int](b, "numbers")

	defer func() {
		if r := recover(); r == nil {
			t.Error("should have panicked")
		}
	}()

	event.Topic[string](b, "numbers")
}

func TestBroker_CloseIsIdempotent(t *testing.T) {
	t.Parallel()

	b := event.NewBroker(event.WithSyncDispatch())
	event.Topic[int](b, "numbers")

	b.Close()
	b.Close()
}

// Close must drain every bus it owns before returning.
func TestBroker_CloseDrainsAllTopics(t *testing.T) {
	t.Parallel()

	b := event.NewBroker(event.WithSyncDispatch())

	const topics = 8
	var received atomic.Int64

	for i := range topics {
		bus := event.Topic[int](b, strconv.Itoa(i))
		bus.Subscribe(func(int) { received.Add(1) })

		if !bus.Publish(1) {
			t.Fatal("publish: got false; want true")
		}
	}

	b.Close()

	if got := received.Load(); got != topics {
		t.Errorf("delivered: got %d; want %d", got, topics)
	}
}

// Topic must stay safe when it races a shutdown.
func TestBroker_TopicDuringClose(t *testing.T) {
	t.Parallel()

	b := event.NewBroker(event.WithSyncDispatch())

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 20 {
				bus := event.Topic[int](b, strconv.Itoa(i*20+j))
				bus.Publish(1)
			}
		}()
	}

	b.Close()
	wg.Wait()

	// Anything created by the racing goroutines after the shutdown is closed
	// on arrival, so a second Close has nothing left to do.
	b.Close()
}
