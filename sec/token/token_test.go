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

package token_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deep-rent/nexus/sec/token"
	"github.com/deep-rent/nexus/sys/schedule"
)

func TestSource_Get_Success(t *testing.T) {
	t.Parallel()

	var fetches atomic.Int32
	fetch := func(ctx context.Context) (string, time.Time, error) {
		fetches.Add(1)
		return "foobar", time.Now().Add(1 * time.Hour), nil
	}

	source := token.NewSource(fetch, token.WithBufferTime(5*time.Minute))

	// First fetch
	tok, err := source.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp, act := "foobar", tok; exp != act {
		t.Errorf("got %q, want %q", act, exp)
	}
	if exp, act := int32(1), fetches.Load(); exp != act {
		t.Errorf("expected %d fetches, got %d", exp, act)
	}

	// Second fetch should be cached
	tok, err = source.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp, act := "foobar", tok; exp != act {
		t.Errorf("got %q, want %q", act, exp)
	}
	if exp, act := int32(1), fetches.Load(); exp != act {
		t.Errorf("expected %d fetches after cache hit, got %d", exp, act)
	}
}

func TestSource_Get_Concurrency(t *testing.T) {
	t.Parallel()

	var fetches atomic.Int32
	fetch := func(ctx context.Context) (string, time.Time, error) {
		fetches.Add(1)
		time.Sleep(50 * time.Millisecond) // Simulate slow fetch
		return "foobar", time.Now().Add(1 * time.Hour), nil
	}

	source := token.NewSource(fetch, token.WithBufferTime(5*time.Minute))

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			_, _ = source.Get(t.Context())
		})
	}
	wg.Wait()

	if exp, act := int32(1), fetches.Load(); exp != act {
		t.Errorf("expected %d fetch due to mutex lock, got %d", exp, act)
	}
}

func TestSource_Get_ExpirationBuffer(t *testing.T) {
	t.Parallel()

	var fetches atomic.Int32
	fetch := func(ctx context.Context) (string, time.Time, error) {
		fetches.Add(1)
		// Expiration is 1 minute from now.
		return "tok", time.Now().Add(1 * time.Minute), nil
	}

	// Buffer is 2 minutes, so it should always be considered expired.
	source := token.NewSource(fetch, token.WithBufferTime(2*time.Minute))

	_, _ = source.Get(t.Context())
	_, _ = source.Get(t.Context())

	if exp, act := int32(2), fetches.Load(); exp != act {
		t.Errorf(
			"expected %d fetches due to buffer forcing expiration, got %d",
			exp, act,
		)
	}
}

func TestSource_Get_Error(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("network failure")

	fetch := func(ctx context.Context) (string, time.Time, error) {
		return "", time.Time{}, wantErr
	}

	source := token.NewSource(fetch, token.WithBufferTime(1*time.Minute))

	_, err := source.Get(t.Context())
	if !errors.Is(err, wantErr) {
		t.Errorf("got %v, want %v", err, wantErr)
	}
}

func TestSource_WithScheduler(t *testing.T) {
	t.Parallel()

	var fetches atomic.Int32
	fetch := func(ctx context.Context) (string, time.Time, error) {
		fetches.Add(1)
		return "foobar", time.Now().Add(10 * time.Millisecond), nil
	}

	sched := schedule.Once(t.Context())

	source := token.NewSource(fetch,
		token.WithBufferTime(5*time.Millisecond),
		token.WithScheduler(sched),
	)

	// The first tick should have triggered a fetch because the expiration time
	// is zero.
	if exp, act := int32(1), fetches.Load(); exp != act {
		t.Fatalf("expected %d fetches after scheduler init, got %d", exp, act)
	}

	// Subsequent calls should return the fetched token.
	tok, err := source.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "foobar" {
		t.Errorf("got %q, want foobar", tok)
	}
}

// One caller cancelling must not fail the fetch for others sharing it. The
// fetch is detached from any single caller's context.
func TestSource_Get_CancellationNotShared(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var fetches atomic.Int32

	fetch := func(ctx context.Context) (string, time.Time, error) {
		fetches.Add(1)
		close(started)
		select {
		case <-release:
			return "tok", time.Now().Add(time.Hour), nil
		case <-ctx.Done():
			return "", time.Time{}, ctx.Err()
		}
	}

	src := token.NewSource(fetch)

	// Caller A owns the in-flight fetch and then gives up.
	ctxA, cancelA := context.WithCancel(t.Context())
	doneA := make(chan error, 1)
	go func() {
		_, err := src.Get(ctxA)
		doneA <- err
	}()

	<-started // A is now inside the shared fetch.

	// Caller B joins the same fetch with a healthy context.
	doneB := make(chan result, 1)
	go func() {
		tok, err := src.Get(t.Context())
		doneB <- result{tok, err}
	}()

	time.Sleep(20 * time.Millisecond) // let B attach to the shared call
	cancelA()

	// A observes its own cancellation.
	select {
	case err := <-doneA:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("caller A: got %v; want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller A did not return")
	}

	// The fetch keeps running; let it finish.
	close(release)

	select {
	case res := <-doneB:
		if res.err != nil {
			t.Errorf("caller B was poisoned by A's cancellation: %v", res.err)
		}
		if res.tok != "tok" {
			t.Errorf("caller B: got token %q; want %q", res.tok, "tok")
		}
	case <-time.After(time.Second):
		t.Fatal("caller B did not return")
	}

	if got := fetches.Load(); got != 1 {
		t.Errorf("fetches: got %d; want 1 (calls must be collapsed)", got)
	}
}

type result struct {
	tok string
	err error
}
