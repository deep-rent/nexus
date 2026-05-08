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

package ports_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/deep-rent/nexus/testutil/ports"
)

func TestFree(t *testing.T) {
	t.Parallel()

	p, err := ports.Free()
	if err != nil {
		t.Fatalf("ports.Free() err = %v", err)
	}
	if p <= 0 {
		t.Errorf("ports.Free() = %d; want > 0", p)
	}
}

func TestFreeT(t *testing.T) {
	t.Parallel()

	p := ports.FreeT(t)
	if p <= 0 {
		t.Errorf("ports.FreeT(t) = %d; want > 0", p)
	}
}

func TestWait(t *testing.T) {
	t.Parallel()

	p := ports.FreeT(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(p))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("net.Listen(tcp, %q) err = %v", addr, err)
	}
	defer func() {
		_ = l.Close()
	}()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	if err := ports.Wait(ctx, "127.0.0.1", p); err != nil {
		t.Errorf("ports.Wait(ctx, 127.0.0.1, %d) err = %v", p, err)
	}
}

func TestWait_Timeout(t *testing.T) {
	t.Parallel()

	p := ports.FreeT(t)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	if err := ports.Wait(ctx, "127.0.0.1", p); err == nil {
		t.Error("ports.Wait() err = nil; want timeout error")
	}
}

func TestWaitT(t *testing.T) {
	t.Parallel()

	p := ports.FreeT(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(p))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("net.Listen(tcp, %q) err = %v", addr, err)
	}
	defer func() {
		_ = l.Close()
	}()

	ports.WaitT(t, "127.0.0.1", p)
}

func TestWaitT_TimeoutCondition(t *testing.T) {
	t.Parallel()

	p := ports.FreeT(t)
	t.Run("fails on timeout", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()

		if err := ports.Wait(ctx, "127.0.0.1", p); err == nil {
			t.Error("ports.Wait() err = nil; want error")
		}
	})
}
