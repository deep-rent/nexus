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

	"github.com/deep-rent/nexus/token"
)

func TestSource_Get_Success(t *testing.T) {
	t.Parallel()

	var fetches atomic.Int32
	fetch := func(ctx context.Context) (string, time.Time, error) {
		fetches.Add(1)
		return "foobar", time.Now().Add(1 * time.Hour), nil
	}

	source := token.NewSource(fetch, 5*time.Minute)

	// First fetch
	tok, err := source.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp, act := "foobar", tok; exp != act {
		t.Errorf("got %q, want %s", act, exp)
	}
	if exp, act := int32(1), fetches.Load(); exp != act {
		t.Errorf("expected %d fetches, got %d", exp, act)
	}

	// Second fetch should be cached
	tok, err = source.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "foobar" {
		t.Errorf("got %q, want foobar", tok)
	}
	if exp, act := int32(1), fetches.Load(); exp != act {
		t.Errorf("expected %d fetches after cache hit, got %d", exp, act)
	}
}

func TestSource_Get_Concurrency(t *testing.T) {
	t.Parallel()

	var fetches int32
	fetch := func(ctx context.Context) (string, time.Time, error) {
		atomic.AddInt32(&fetches, 1)
		time.Sleep(50 * time.Millisecond) // Simulate slow fetch
		return "foobar", time.Now().Add(1 * time.Hour), nil
	}

	source := token.NewSource(fetch, 5*time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = source.Get(t.Context())
		}()
	}
	wg.Wait()

	if atomic.LoadInt32(&fetches) != 1 {
		t.Errorf("expected exactly 1 fetch due to mutex lock, got %d", fetches)
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
	source := token.NewSource(fetch, 2*time.Minute)

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

	source := token.NewSource(fetch, 1*time.Minute)

	_, err := source.Get(t.Context())
	if !errors.Is(err, wantErr) {
		t.Errorf("got %v, want %v", err, wantErr)
	}
}
