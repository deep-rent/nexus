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
	b := event.NewBus(event.WithSyncDispatch[int]())
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
	b := event.NewBus(event.WithSyncDispatch[int]())
	defer b.Close()

	var wg sync.WaitGroup
	var c int32

	unsub := b.Subscribe(func(v int) {
		atomic.AddInt32(&c, 1)
		wg.Done()
	})

	wg.Add(1)
	require.True(t, b.Publish(1))
	wg.Wait()

	unsub()
	unsub()

	require.True(t, b.Publish(2))
	time.Sleep(10 * time.Millisecond)

	assert.Equal(t, int32(1), atomic.LoadInt32(&c))
}

func TestBus_Options(t *testing.T) {
	t.Parallel()

	tcs := []struct {
		n    string
		opts []event.Option[int]
	}{
		{"defaults", nil},
		{"sync", []event.Option[int]{event.WithSyncDispatch[int]()}},
		{"blocking", []event.Option[int]{event.WithBlockingWait[int]()}},
		{"adaptive", []event.Option[int]{event.WithAdaptiveWait[int]()}},
		{"size", []event.Option[int]{event.WithSize[int](16)}},
		{"mode", []event.Option[int]{event.WithOverflowMode[int](event.DropNewest)}},
		{"logger", []event.Option[int]{event.WithLogger[int](slog.Default())}},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.n, func(t *testing.T) {
			t.Parallel()
			b := event.NewBus(tc.opts...)
			defer b.Close()
			assert.NotNil(t, b)
			assert.True(t, b.Publish(1))
		})
	}
}

func TestBus_PanicRecovery(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&buf, nil))

	b := event.NewBus(
		event.WithSyncDispatch[int](),
		event.WithLogger[int](l),
	)
	defer b.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	b.Subscribe(func(v int) {
		defer wg.Done()
		if v == 1 {
			panic("test panic")
		}
	})

	require.True(t, b.Publish(1))
	require.True(t, b.Publish(2))
	wg.Wait()

	assert.Contains(t, buf.String(), "Subscriber panicked")
}

func TestBus_Concurrency_SPMC(t *testing.T) {
	t.Parallel()
	b := event.NewBus(event.WithSize[int](4096))
	defer b.Close()

	var wg sync.WaitGroup
	var sum int64

	sc := 5
	pc := 10
	mc := 1000

	wg.Add(mc * pc * sc)

	for i := 0; i < sc; i++ {
		b.Subscribe(func(v int) {
			atomic.AddInt64(&sum, int64(v))
			wg.Done()
		})
	}

	var swg sync.WaitGroup
	swg.Add(pc)

	for i := 0; i < pc; i++ {
		go func() {
			swg.Done()
			swg.Wait()
			for j := 0; j < mc; j++ {
				for !b.Publish(1) {
					runtime.Gosched()
				}
			}
		}()
	}

	wg.Wait()
	assert.Equal(t, int64(pc*mc*sc), atomic.LoadInt64(&sum))
}

func TestBroker_Topic(t *testing.T) {
	t.Parallel()
	br := event.NewBroker()
	defer br.Close()

	b1 := event.Topic[int](br, "t1")
	require.NotNil(t, b1)

	b2 := event.Topic[int](br, "t1")
	assert.Same(t, b1, b2)

	assert.Panics(t, func() {
		event.Topic[string](br, "t1")
	})
}

func TestBroker_Close(t *testing.T) {
	t.Parallel()
	br := event.NewBroker()

	b1 := event.Topic[int](br, "t1")
	b2 := event.Topic[string](br, "t2")

	require.True(t, b1.Publish(1))
	require.True(t, b2.Publish("a"))

	br.Close()

	assert.False(t, b1.Publish(2))
	assert.False(t, b2.Publish("b"))
}

type stubWait struct {
	snooze int32
	signal int32
}

func (w *stubWait) Snooze(_ int) { atomic.AddInt32(&w.snooze, 1) }
func (w *stubWait) Signal()      { atomic.AddInt32(&w.signal, 1) }

func TestBus_CustomWaitStrategy(t *testing.T) {
	t.Parallel()
	w := &stubWait{}
	b := event.NewBus(event.WithCustomWaitStrategy[int](w))

	assert.True(t, b.Publish(1))
	b.Close()

	assert.GreaterOrEqual(t, atomic.LoadInt32(&w.signal), int32(1))
}

type pauseWait struct {
	sem chan struct{}
}

func (w *pauseWait) Snooze(_ int) { <-w.sem }
func (w *pauseWait) Signal()      {}

func TestBus_DropPolicy(t *testing.T) {
	t.Parallel()
	w := &pauseWait{sem: make(chan struct{})}
	b := event.NewBus(
		event.WithSize[int](2),
		event.WithOverflowMode[int](event.DropNewest),
		event.WithCustomWaitStrategy[int](w),
	)

	assert.True(t, b.Publish(1))
	assert.True(t, b.Publish(2))
	assert.False(t, b.Publish(3))

	close(w.sem)
	b.Close()
}
