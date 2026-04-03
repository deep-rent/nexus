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

package app_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/deep-rent/nexus/app"
)

func TestRun_Success(t *testing.T) {
	t.Parallel()

	r := func(context.Context) error { return nil }

	if err := app.Run(r); err != nil {
		t.Fatalf("Run(r) = %v; want nil", err)
	}
}

func TestRun_Error(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("an error")
	r := func(context.Context) error { return wantErr }

	err := app.Run(r)
	if err == nil {
		t.Fatalf("Run(r) = nil; want error")
	}

	if !errors.Is(err, wantErr) {
		t.Errorf("Run(r) error = %v; want %v", err, wantErr)
	}
}

func TestRun_Panic(t *testing.T) {
	t.Parallel()

	const panicMsg = "something went terribly wrong"
	r := func(context.Context) error {
		panic(panicMsg)
	}

	err := app.Run(r)
	if err == nil {
		t.Fatalf("Run(r) = nil; want error")
	}

	tests := []struct {
		name string
		want string
	}{
		{"panic prefix", "application panic"},
		{"panic message", panicMsg},
		{"file location", "app_test.go"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf(
					"Run(r) error = %q; want to contain %q",
					err.Error(), tt.want,
				)
			}
		})
	}
}

func TestRun_SignalShutdown(t *testing.T) {
	t.Parallel()

	done := make(chan struct{})
	r := func(ctx context.Context) error {
		<-ctx.Done()
		time.Sleep(20 * time.Millisecond)
		close(done)
		return nil
	}

	sig := syscall.SIGUSR1
	errCh := make(chan error, 1)

	go func() {
		errCh <- app.Run(r, app.WithSignals(sig))
	}()

	time.Sleep(50 * time.Millisecond)

	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("os.FindProcess(os.Getpid()) = %v; want nil", err)
	}

	if err := p.Signal(sig); err != nil {
		t.Fatalf("p.Signal(sig) = %v; want nil", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run() = %v; want nil", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("did not return after shutdown signal")
	}

	select {
	case <-done:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("cleanup did not finish in time")
	}
}

func TestRun_ContextCanceledIgnored(t *testing.T) {
	t.Parallel()

	sig := syscall.SIGUSR1
	r := func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.Run(r, app.WithSignals(sig))
	}()

	time.Sleep(50 * time.Millisecond)

	p, _ := os.FindProcess(os.Getpid())
	_ = p.Signal(sig)

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run() = %v; want nil", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for shutdown")
	}
}

func TestRun_ShutdownTimeout(t *testing.T) {
	t.Parallel()

	timeout := 20 * time.Millisecond
	r := func(ctx context.Context) error {
		<-ctx.Done()
		time.Sleep(5 * timeout)
		return nil
	}

	sig := syscall.SIGUSR1
	errCh := make(chan error, 1)

	go func() {
		errCh <- app.Run(r, app.WithSignals(sig), app.WithTimeout(timeout))
	}()

	time.Sleep(50 * time.Millisecond)

	p, _ := os.FindProcess(os.Getpid())
	_ = p.Signal(sig)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("Run() = nil; want error")
		}

		if want := "shutdown timed out"; !strings.Contains(err.Error(), want) {
			t.Errorf("Run() error = %q; want to contain %q", err.Error(), want)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("did not time out as expected")
	}
}

func TestRun_CancelParentContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	r := func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.Run(r, app.WithContext(ctx))
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run() = %v; want nil", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("did not return after parent context was canceled")
	}
}

func TestRun_WithLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	r := func(context.Context) error { return nil }

	if err := app.Run(r, app.WithLogger(logger)); err != nil {
		t.Fatalf("Run() = %v; want nil", err)
	}

	logs := buf.String()
	tests := []struct {
		name string
		want string
	}{
		{"log started", "Application started"},
		{"log stopped", "Application stopped"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(logs, tt.want) {
				t.Errorf("logs = %q; want to contain %q", logs, tt.want)
			}
		})
	}
}

func TestRunAll_Success(t *testing.T) {
	t.Parallel()

	r1 := func(ctx context.Context) error { return nil }
	r2 := func(ctx context.Context) error { return nil }

	if err := app.RunAll([]app.Runnable{r1, r2}); err != nil {
		t.Fatalf("RunAll() = %v; want nil", err)
	}
}

func TestRunAll_CascadingError(t *testing.T) {
	t.Parallel()

	errTriggered := errors.New("worker 1 failed")
	var canceled bool

	r1 := func(ctx context.Context) error {
		time.Sleep(10 * time.Millisecond)
		return errTriggered
	}

	r2 := func(ctx context.Context) error {
		<-ctx.Done()
		if errors.Is(ctx.Err(), context.Canceled) {
			canceled = true
		}
		return nil
	}

	err := app.RunAll([]app.Runnable{r1, r2})

	if err == nil {
		t.Fatalf("RunAll() = nil; want error")
	}

	if !errors.Is(err, errTriggered) {
		t.Errorf("RunAll() error = %v; want %v", err, errTriggered)
	}

	if !canceled {
		t.Errorf("canceled = %t; want true", canceled)
	}
}

func TestRunAll_CascadingPanic(t *testing.T) {
	t.Parallel()

	var canceled bool

	r1 := func(ctx context.Context) error {
		time.Sleep(10 * time.Millisecond)
		panic("worker 1 panicked")
	}

	r2 := func(ctx context.Context) error {
		<-ctx.Done()
		if errors.Is(ctx.Err(), context.Canceled) {
			canceled = true
		}
		return nil
	}

	err := app.RunAll([]app.Runnable{r1, r2})

	if err == nil {
		t.Fatalf("RunAll() = nil; want error")
	}

	if got, want := err.Error(),
		"worker 1 panicked"; !strings.Contains(got, want) {
		t.Errorf("RunAll() error = %q; want to contain %q", got, want)
	}

	if !canceled {
		t.Errorf("canceled = %t; want true", canceled)
	}
}

func TestRunAll_SignalShutdownAll(t *testing.T) {
	t.Parallel()

	sig := syscall.SIGUSR1
	var (
		canceled1 bool
		canceled2 bool
	)

	r1 := func(ctx context.Context) error {
		<-ctx.Done()
		canceled1 = true
		return nil
	}
	r2 := func(ctx context.Context) error {
		<-ctx.Done()
		canceled2 = true
		return nil
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.RunAll([]app.Runnable{r1, r2}, app.WithSignals(sig))
	}()

	time.Sleep(50 * time.Millisecond)

	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("os.FindProcess(os.Getpid()) = %v; want nil", err)
	}

	if err := p.Signal(sig); err != nil {
		t.Fatalf("p.Signal(sig) = %v; want nil", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunAll() = %v; want nil", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for shutdown")
	}

	if !canceled1 {
		t.Errorf("canceled1 = %t; want true", canceled1)
	}

	if !canceled2 {
		t.Errorf("canceled2 = %t; want true", canceled2)
	}
}

func TestRunAll_ShutdownTimeoutOnCascadingError(t *testing.T) {
	t.Parallel()

	timeout := 20 * time.Millisecond
	errDone := errors.New("worker 1 failed")

	r1 := func(ctx context.Context) error {
		return errDone
	}

	r2 := func(ctx context.Context) error {
		<-ctx.Done()
		time.Sleep(5 * timeout)
		return nil
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.RunAll([]app.Runnable{r1, r2}, app.WithTimeout(timeout))
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("RunAll() = nil; want error")
		}

		if got, want := err.Error(),
			"shutdown timed out"; !strings.Contains(got, want) {
			t.Errorf("RunAll() error = %q; want to contain %q", got, want)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("did not time out as expected")
	}
}
