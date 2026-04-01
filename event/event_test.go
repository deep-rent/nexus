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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deep-rent/nexus/event"
)

func TestBus_Basic(t *testing.T) {
	t.Parallel()
	b := event.NewBus[int](event.WithSyncDispatch())
	defer b.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	var sum int64
	b.Subscribe(func(v int) {
		atomic.AddInt64(&sum, int64(v))
		wg.Done()
	})

	assert.True(t, b.Publish(10))
	assert.True(t, b.Publish(20))

	wg.Wait()
	assert.Equal(t, int64(30), atomic.LoadInt64(&sum))
}

func TestBus_Unsubscribe(t *testing.T) {
	t.Parallel()
	bus := event.NewBus[int](event.WithSyncDispatch())
	defer bus.Close()

	var wg sync.WaitGroup
	var c int32

	unsub := bus.Subscribe(func(v int) {
		atomic.AddInt32(&c, 1)
		wg.Done()
	})

	wg.Add(1)
	require.True(t, bus.Publish(1))
	wg.Wait()

	unsub()
	unsub()

	require.True(t, bus.Publish(2))
	time.Sleep(10 * time.Millisecond)

	assert.Equal(t, int32(1), atomic.LoadInt32(&c))
}

func TestBus_Options(t *testing.T) {
	t.Parallel()

	tests := []struct {
		n    string
		opts []event.Option
	}{
		{"defaults", nil},
		{"sync", []event.Option{event.WithSyncDispatch()}},
		{"blocking", []event.Option{event.WithBlockingWait()}},
		{"adaptive", []event.Option{event.WithAdaptiveWait()}},
		{"size_valid", []event.Option{event.WithSize(16)}},
		{"size_ignored", []event.Option{event.WithSize(-10)}},
		{"mode", []event.Option{event.WithOverflowMode(event.DropNewest)}},
		{"logger", []event.Option{event.WithLogger(slog.Default())}},
	}

	for _, tc := range tests {
		t.Run(tc.n, func(t *testing.T) {
			t.Parallel()
			b := event.NewBus[int](tc.opts...)
			defer b.Close()
			assert.NotNil(t, b)
			assert.True(t, b.Publish(1))
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

	require.True(t, bus.Publish(1))
	require.True(t, bus.Publish(2))
	wg.Wait()

	assert.Contains(t, buf.String(), "Subscriber panicked")
	assert.Contains(t, buf.String(), "sync panic")
}

func TestBroker_Topic(t *testing.T) {
	t.Parallel()
	broker := event.NewBroker()
	defer broker.Close()

	bus1 := event.Topic[int](broker, "t1")
	require.NotNil(t, bus1)

	bus2 := event.Topic[int](broker, "t1")
	assert.Same(t, bus1, bus2)

	assert.PanicsWithValue(
		t,
		`event: topic "t1" exists but expects a different event type`,
		func() {
			event.Topic[string](broker, "t1")
		},
	)
}

func TestBus_Concurrency_MPMC(t *testing.T) {
	t.Parallel()
	bus := event.NewBus[int](event.WithSize(4096), event.WithSyncDispatch())
	defer bus.Close()

	var wg sync.WaitGroup
	var sum int64

	sc := 5
	pc := 10
	mc := 1000

	wg.Add(mc * pc * sc)

	for range sc {
		bus.Subscribe(func(v int) {
			atomic.AddInt64(&sum, int64(v))
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

	assert.Equal(t, int64(pc*mc*sc), atomic.LoadInt64(&sum))
}

func TestBroker_Options(t *testing.T) {
	t.Parallel()
	w := &stubWait{}
	broker := event.NewBroker(
		event.WithCustomWaitStrategy(w),
		event.WithSyncDispatch(),
	)
	defer broker.Close()

	b := event.Topic[int](broker, "t1")
	require.True(t, b.Publish(1))
	b.Close()

	assert.GreaterOrEqual(t, atomic.LoadInt32(&w.signal), int32(1))
}

func TestBroker_Close(t *testing.T) {
	t.Parallel()
	broker := event.NewBroker()

	bus1 := event.Topic[int](broker, "t1")
	bus2 := event.Topic[string](broker, "t2")

	require.True(t, bus1.Publish(1))
	require.True(t, bus2.Publish("a"))

	broker.Close()

	assert.False(t, bus1.Publish(2))
	assert.False(t, bus2.Publish("b"))
}

type stubWait struct {
	snooze int32
	signal int32
}

func (w *stubWait) Snooze(_ int) { atomic.AddInt32(&w.snooze, 1) }
func (w *stubWait) Signal()      { atomic.AddInt32(&w.signal, 1) }

var _ event.WaitStrategy = (*stubWait)(nil)

func TestBus_CustomWaitStrategy(t *testing.T) {
	t.Parallel()
	w := &stubWait{}
	bus := event.NewBus[int](event.WithCustomWaitStrategy(w))

	assert.True(t, bus.Publish(1))
	bus.Close()

	assert.GreaterOrEqual(t, atomic.LoadInt32(&w.signal), int32(1))
}

type pauseWait struct {
	sem chan struct{}
}

func (w *pauseWait) Snooze(_ int) { <-w.sem }
func (w *pauseWait) Signal()      {}

var _ event.WaitStrategy = (*pauseWait)(nil)

func TestBus_DropPolicy(t *testing.T) {
	t.Parallel()
	w := &pauseWait{sem: make(chan struct{})}
	bus := event.NewBus[int](
		event.WithSize(2),
		event.WithOverflowMode(event.DropNewest),
		event.WithCustomWaitStrategy(w),
	)

	assert.True(t, bus.Publish(1))
	assert.True(t, bus.Publish(2))
	assert.False(t, bus.Publish(3))

	close(w.sem)
	bus.Close()
}

type buffer struct {
	mu sync.Mutex
	wb bytes.Buffer
}

func (b *buffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.wb.Write(p)
}

func (b *buffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.wb.String()
}

var _ io.Writer = (*buffer)(nil)

func TestBus_PanicRecovery_Async(t *testing.T) {
	t.Parallel()

	buf := &buffer{}
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

	require.True(t, bus.Publish(1))
	require.True(t, bus.Publish(2))
	wg.Wait()

	assert.Eventually(t, func() bool {
		pt1 := []byte("Subscriber panicked")
		pt2 := []byte("async panic")

		out := []byte(buf.String())
		return bytes.Contains(out, pt1) && bytes.Contains(out, pt2)
	},
		100*time.Millisecond, 5*time.Millisecond,
		"expected panic logs were not written in time",
	)
}

func TestBroker_ConcurrentTopicCreation(t *testing.T) {
	t.Parallel()
	broker := event.NewBroker()
	defer broker.Close()

	gr := 100
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
	require.NotNil(t, first)

	for _, b := range buses[1:] {
		assert.Same(t, first, b)
	}
}

func TestBus_ConcurrentSubUnsub(t *testing.T) {
	t.Parallel()
	bus := event.NewBus[int]()
	defer bus.Close()

	var pub sync.WaitGroup
	pub.Add(1)

	var stop atomic.Bool

	go func() {
		defer pub.Done()
		for !stop.Load() {
			bus.Publish(1)
			runtime.Gosched()
		}
	}()

	var sub sync.WaitGroup
	mc := 50
	sub.Add(mc)

	for range mc {
		go func() {
			defer sub.Done()
			var c int32

			unsub := bus.Subscribe(func(v int) {
				atomic.AddInt32(&c, 1)
			})

			time.Sleep(2 * time.Millisecond)
			unsub()

			assert.Greater(t, atomic.LoadInt32(&c), int32(0))
		}()
	}

	sub.Wait()
	stop.Store(true)
	pub.Wait()
}
