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
	"github.com/stretchr/testify/require"
)

func TestFree(t *testing.T) {
	p, err := ports.Free()
	require.NoError(t, err)
	require.Greater(t, p, 0)
}

func TestFreeT(t *testing.T) {
	p := ports.FreeT(t)
	require.Greater(t, p, 0)
}

func TestWait(t *testing.T) {
	p := ports.FreeT(t)
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
	require.NoError(t, err)
	defer func() {
		_ = l.Close()
	}()

	ctx, c := context.WithTimeout(t.Context(), time.Second)
	defer c()

	err = ports.Wait(ctx, "127.0.0.1", p)
	require.NoError(t, err)
}

func TestWaitTimeout(t *testing.T) {
	p := ports.FreeT(t)
	ctx, c := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer c()

	err := ports.Wait(ctx, "127.0.0.1", p)
	require.Error(t, err)
}

func TestWaitT(t *testing.T) {
	p := ports.FreeT(t)
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
	require.NoError(t, err)
	defer func() {
		_ = l.Close()
	}()

	ports.WaitT(t, "127.0.0.1", p)
}

func TestWaitT_Timeout(t *testing.T) {
	p := ports.FreeT(t)
	t.Run("fails on timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()

		err := ports.Wait(ctx, "127.0.0.1", p)
		require.Error(t, err)
	})
}
