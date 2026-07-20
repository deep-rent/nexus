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
	"bytes"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deep-rent/nexus/event"
)

func TestBus_Basic(t *testing.T) {
	t.Parallel()
	bus := event.NewBus[int](event.WithSyncDispatch())
	defer bus.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	var sum atomic.Int64
	bus.Subscribe(func(v int) {
		sum.Add(int64(v))
		wg.Done()
	})

	event1 := 10
	if ok := bus.Publish(event1); !ok {
		t.Errorf("publishing %d: got %t; want %t", event1, ok, true)
	}

	event2 := 20
	if ok := bus.Publish(event2); !ok {
		t.Errorf("publishing %d: got %t; want %t", event2, ok, true)
	}

	wg.Wait()
	if got, want := sum.Load(), int64(event1+event2); got != want {
		t.Errorf("sum: got %d; want %d", got, want)
	}
}

func TestBus_Unsubscribe(t *testing.T) {
	t.Parallel()
	bus := event.NewBus[int](event.WithSyncDispatch())
	defer bus.Close()

	var wg sync.WaitGroup
	var c atomic.Int32

	unsub := bus.Subscribe(func(_ int) {
		c.Add(1)
		wg.Done()
	})

	wg.Add(1)
	if ok := bus.Publish(1); !ok {
		t.Fatalf("publishing 1: got %t; want %t", ok, true)
	}
	wg.Wait()

	unsub()
	unsub()

	if ok := bus.Publish(2); !ok {
		t.Errorf("publishing 2: got %t; want %t", ok, true)
	}
	time.Sleep(10 * time.Millisecond)

	if got, want := c.Load(), int32(1); got != want {
		t.Errorf("count: got %d; want %d", got, want)
	}
}

func TestBus_Options(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []event.Option
	}{
		{"defaults", nil},
		{"sync", []event.Option{event.WithSyncDispatch()}},
		{"blocking", []event.Option{event.WithBlockingWait()}},
		{"adaptive", []event.Option{event.WithAdaptiveWait()}},
		{"size valid", []event.Option{event.WithSize(16)}},
		{"size ignored", []event.Option{event.WithSize(-10)}},
		{"mode", []event.Option{event.WithOverflowMode(event.DropNewest)}},
		{"logger", []event.Option{event.WithLogger(slog.Default())}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := event.NewBus[int](tt.opts...)
			defer b.Close()

			if b == nil {
				t.Fatal("bus should not be nil")
			}
			if ok := b.Publish(1); !ok {
				t.Errorf("publishing 1: got %t; want %t", ok, true)
			}
		})
	}
}

func TestBus_PanicRecovery_Sync(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	bus := event.NewBus[int](
		event.WithSyncDispatch(),
		event.WithLogger(logger),
	)
	defer bus.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	bus.Subscribe(func(v int) {
		defer wg.Done()
		if v == 1 {
			panic("sync panic")
		}
	})

	if ok := bus.Publish(1); !ok {
		t.Fatalf("publishing 1: got %t; want %t", ok, true)
	}
	if ok := bus.Publish(2); !ok {
		t.Fatalf("publishing 2: got %t; want %t", ok, true)
	}
	wg.Wait()

	out := buf.String()
	if want := "Subscriber panicked"; !strings.Contains(out, want) {
		t.Errorf("want match for %q; got %q", want, out)
	}
	if want := "sync panic"; !strings.Contains(out, want) {
		t.Errorf("want match for %q; got %q", want, out)
	}
}

func TestBroker_Topic(t *testing.T) {
	t.Parallel()
	broker := event.NewBroker()
	defer broker.Close()

	bus1 := event.Topic[int](broker, "t1")
	if bus1 == nil {
		t.Fatal("bus should not be nil")
	}

	bus2 := event.Topic[int](broker, "t1")
	if bus1 != bus2 {
		t.Error("buses for the same topic should be identical")
	}

	defer func() {
		want := `topic "t1" exists but expects a different event type`
		if r := recover(); r != want {
			t.Errorf("panic value: got %v; want %v", r, want)
		}
	}()

	event.Topic[string](broker, "t1")
}

func TestBus_Concurrency_MPMC(t *testing.T) {
	t.Parallel()
	bus := event.NewBus[int](event.WithSize(4096), event.WithSyncDispatch())
	defer bus.Close()

	var wg sync.WaitGroup
	var sum atomic.Int64

	const (
		sc = 5
		pc = 10
		mc = 1000
	)

	wg.Add(mc * pc * sc)

	for range sc {
		bus.Subscribe(func(v int) {
			sum.Add(int64(v))
			wg.Done()
		})
	}

	var ready sync.WaitGroup
	ready.Add(pc)

	for range pc {
		go func() {
			ready.Done()
			ready.Wait()
			for range mc {
				for !bus.Publish(1) {
					runtime.Gosched()
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout due to dropped events or deadlock")
	}

	if got, want := sum.Load(), int64(pc*mc*sc); got != want {
		t.Errorf("sum: got %d; want %d", got, want)
	}
}

func TestBroker_Options(t *testing.T) {
	t.Parallel()
	w := &mockWait{}
	broker := event.NewBroker(
		event.WithWaitStrategy(func() event.WaitStrategy { return w }),
		event.WithSyncDispatch(),
	)
	defer broker.Close()

	b := event.Topic[int](broker, "t1")
	if ok := b.Publish(1); !ok {
		t.Fatalf("publishing 1: got %t; want %t", ok, true)
	}
	b.Close()

	if got := w.signalCount.Load(); got < 1 {
		t.Errorf("signal count: got %d; want >= 1", got)
	}
}

func TestBroker_Close(t *testing.T) {
	t.Parallel()
	broker := event.NewBroker()

	bus1 := event.Topic[int](broker, "t1")
	bus2 := event.Topic[string](broker, "t2")

	if ok := bus1.Publish(1); !ok {
		t.Fatalf("publishing 1: got %t; want %t", ok, true)
	}
	if ok := bus2.Publish("a"); !ok {
		t.Fatalf("publishing \"a\": got %t; want %t", ok, true)
	}

	broker.Close()

	if ok := bus1.Publish(2); ok {
		t.Errorf("publishing 2 after close: got %t; want %t", ok, false)
	}
	if ok := bus2.Publish("b"); ok {
		t.Errorf("publishing \"b\" after close: got %t; want %t", ok, false)
	}
}

type mockWait struct {
	snoozeCount atomic.Int32
	signalCount atomic.Int32
}

func (w *mockWait) Snooze(_ int) { w.snoozeCount.Add(1) }
func (w *mockWait) Signal()      { w.signalCount.Add(1) }

var _ event.WaitStrategy = (*mockWait)(nil)

func TestBus_CustomWaitStrategy(t *testing.T) {
	t.Parallel()
	w := &mockWait{}
	bus := event.NewBus[int](event.WithWaitStrategy(func() event.WaitStrategy { return w }))

	if ok := bus.Publish(1); !ok {
		t.Errorf("publishing 1: got %t; want %t", ok, true)
	}
	bus.Close()

	if got := w.signalCount.Load(); got < 1 {
		t.Errorf("signal count: got %d; want >= 1", got)
	}
}

type mockPauseWait struct {
	sem chan struct{}
}

func (w *mockPauseWait) Snooze(_ int) { <-w.sem }
func (w *mockPauseWait) Signal()      {}

var _ event.WaitStrategy = (*mockPauseWait)(nil)

func TestBus_DropNewestMode(t *testing.T) {
	t.Parallel()
	w := &mockPauseWait{sem: make(chan struct{})}
	bus := event.NewBus[int](
		event.WithSize(2),
		event.WithOverflowMode(event.DropNewest),
		event.WithWaitStrategy(func() event.WaitStrategy { return w }),
	)

	if ok := bus.Publish(1); !ok {
		t.Errorf("publishing 1: got %t; want %t", ok, true)
	}
	if ok := bus.Publish(2); !ok {
		t.Errorf("publishing 2: got %t; want %t", ok, true)
	}
	if ok := bus.Publish(3); ok {
		t.Errorf("publishing 3 on overflow: got %t; want %t", ok, false)
	}

	close(w.sem)
	bus.Close()
}

func TestBus_DropOldestMode(t *testing.T) {
	t.Parallel()
	w := &mockPauseWait{sem: make(chan struct{})}
	bus := event.NewBus[int](
		event.WithSize(2),
		event.WithOverflowMode(event.DropOldest),
		event.WithWaitStrategy(func() event.WaitStrategy { return w }),
	)

	if ok := bus.Publish(1); !ok {
		t.Errorf("publishing 1: got %t; want %t", ok, true)
	}
	if ok := bus.Publish(2); !ok {
		t.Errorf("publishing 2: got %t; want %t", ok, true)
	}
	if ok := bus.Publish(3); !ok {
		t.Errorf("publishing 3 on overflow: got %t; want %t", ok, true)
	}

	close(w.sem)
	bus.Close()
}

type mockSafeBuffer struct {
	mu sync.Mutex
	wb bytes.Buffer
}

func (b *mockSafeBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.wb.Write(p)
}

func (b *mockSafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.wb.String()
}

var _ io.Writer = (*mockSafeBuffer)(nil)

func TestBus_PanicRecovery_Async(t *testing.T) {
	t.Parallel()

	buf := &mockSafeBuffer{}
	logger := slog.New(slog.NewTextHandler(buf, nil))

	bus := event.NewBus[int](
		event.WithLogger(logger),
	)
	defer bus.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	bus.Subscribe(func(v int) {
		defer wg.Done()
		if v == 1 {
			panic("async panic")
		}
	})

	event1 := 1
	if ok := bus.Publish(event1); !ok {
		t.Fatalf("publishing %d: got %t; want %t", event1, ok, true)
	}
	event2 := 2
	if ok := bus.Publish(event2); !ok {
		t.Fatalf("publishing %d: got %t; want %t", event2, ok, true)
	}

	wg.Wait()

	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		out := buf.String()
		if strings.Contains(out, "Subscriber panicked") &&
			strings.Contains(out, "async panic") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("panic logs should have been written in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestBroker_ConcurrentTopicCreation(t *testing.T) {
	t.Parallel()
	broker := event.NewBroker()
	defer broker.Close()

	const gr = 100
	var wg sync.WaitGroup
	wg.Add(gr)

	buses := make([]*event.Bus[int], gr)

	for i := range gr {
		go func(idx int) {
			defer wg.Done()
			buses[idx] = event.Topic[int](broker, "hot-topic")
		}(i)
	}

	wg.Wait()

	first := buses[0]
	if first == nil {
		t.Fatal("first bus should not be nil")
	}

	for i, b := range buses[1:] {
		if first != b {
			t.Errorf("bus at index %d should be identical to the first", i+1)
		}
	}
}

// Subscribing and unsubscribing while events are flowing must be safe, and a
// subscriber that is attached long enough must actually receive something.
func TestBus_ConcurrentSubUnsub(t *testing.T) {
	t.Parallel()

	bus := event.NewBus[int]()
	defer bus.Close()

	var (
		pub  sync.WaitGroup
		stop atomic.Bool
	)

	pub.Add(1)
	go func() {
		defer pub.Done()
		for !stop.Load() {
			bus.Publish(1)
			runtime.Gosched()
		}
	}()

	var sub sync.WaitGroup
	const subscribers = 50

	for range subscribers {
		sub.Add(1)
		go func() {
			defer sub.Done()

			// Waiting for a delivery beats sleeping for a fixed window: under
			// load a subscriber can legitimately see nothing for a few
			// milliseconds, which used to fail this test spuriously.
			got := make(chan struct{})
			var once sync.Once

			unsub := bus.Subscribe(func(int) {
				once.Do(func() { close(got) })
			})
			defer unsub()

			select {
			case <-got:
			case <-time.After(10 * time.Second):
				t.Error("subscriber received no event")
			}
		}()
	}

	sub.Wait()
	stop.Store(true)
	pub.Wait()
}

func TestOverflowMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode event.OverflowMode
		// full reports how many of the surplus publishes are accepted once
		// the buffer is saturated.
		accepts bool
	}{
		{"drop newest", event.DropNewest, false},
		{"drop oldest", event.DropOldest, true},
		{"unrecognized", event.OverflowMode(42), true}, // Falls back to Block.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.mode == event.OverflowMode(42) {
				// Block would wait for a consumer that never arrives, so only
				// the mapping is exercised here.
				bus := event.NewBus[int](
					event.WithOverflowMode(tt.mode),
					event.WithSyncDispatch(),
				)
				defer bus.Close()

				if !bus.Publish(1) {
					t.Error("publish: got false; want true")
				}
				return
			}

			// No subscriber and a tiny buffer, so the queue saturates.
			bus := event.NewBus[int](
				event.WithSize(2),
				event.WithOverflowMode(tt.mode),
				event.WithSyncDispatch(),
				event.WithBlockingWait(),
			)
			defer bus.Close()

			var accepted int
			for range 64 {
				if bus.Publish(1) {
					accepted++
				}
			}

			if tt.accepts && accepted == 0 {
				t.Error("accepted no events; want the oldest to be evicted")
			}

			if !tt.accepts && accepted == 64 {
				t.Error("accepted every event; want the newest to be dropped")
			}
		})
	}
}
