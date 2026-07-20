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
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/deep-rent/nexus/app"
)

// settle is the grace period allowed for a runner to reach a state that should
// be reached almost immediately.
const settle = 500 * time.Millisecond

// blocked returns a component that signals readiness, closes started, and then
// blocks until its context is canceled.
func blocked(started chan<- struct{}) app.Component {
	return func(ctx context.Context) error {
		app.Ready(ctx)
		close(started)
		<-ctx.Done()
		return nil
	}
}

// await blocks until ch is closed, failing the test if that takes too long.
func await(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(settle):
		t.Fatalf("timed out waiting for %s", msg)
	}
}

// result blocks until err yields a value, failing the test if that takes too
// long.
func result(t *testing.T, err <-chan error, msg string) error {
	t.Helper()
	select {
	case e := <-err:
		return e
	case <-time.After(settle):
		t.Fatalf("timed out waiting for %s", msg)
		return nil
	}
}

// launch runs components in the background and returns a channel carrying the
// result of [app.RunAll].
func launch(components []app.Component, opts ...app.Option) <-chan error {
	errCh := make(chan error, 1)
	go func() { errCh <- app.RunAll(components, opts...) }()
	return errCh
}

// interrupt sends sig to the test process.
func interrupt(t *testing.T, sig os.Signal) {
	t.Helper()
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("finding process: should not have returned an error: %v", err)
	}
	if err := p.Signal(sig); err != nil {
		t.Fatalf("sending signal: should not have returned an error: %v", err)
	}
}

func TestRun_Success(t *testing.T) {
	t.Parallel()

	c := func(context.Context) error { return nil }

	if err := app.Run(c); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
}

func TestRun_Error(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("an error")
	c := func(context.Context) error { return wantErr }

	err := app.Run(c)
	if err == nil {
		t.Fatal("should have returned an error")
	}

	if !errors.Is(err, wantErr) {
		t.Errorf("got %v; want %v", err, wantErr)
	}
}

func TestRun_Panic(t *testing.T) {
	t.Parallel()

	const msg = "something went terribly wrong"
	c := func(context.Context) error { panic(msg) }

	err := app.Run(c)
	if err == nil {
		t.Fatal("should have returned an error")
	}

	var panicErr *app.PanicError
	if !errors.As(err, &panicErr) {
		t.Fatalf("error: got %T; want *app.PanicError", err)
	}

	if got := panicErr.Value; got != msg {
		t.Errorf("panic value: got %v; want %q", got, msg)
	}

	if len(panicErr.Stack) == 0 {
		t.Error("panic stack: got empty; want a stack trace")
	}
}

func TestRun_PanicWithError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("an error")
	c := func(context.Context) error { panic(wantErr) }

	err := app.Run(c)
	if !errors.Is(err, wantErr) {
		t.Errorf("got %v; want %v", err, wantErr)
	}
}

func TestRun_ContextCanceledIgnored(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	c := func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}

	errCh := launch([]app.Component{c}, app.WithContext(ctx))
	cancel()

	if err := result(t, errCh, "shutdown"); err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}
}

func TestRun_CancelParentContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	started := make(chan struct{})
	errCh := launch(
		[]app.Component{blocked(started)},
		app.WithContext(ctx),
	)

	await(t, started, "component start")
	cancel()

	if err := result(t, errCh, "shutdown"); err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}
}

func TestRun_ShutdownTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	timeout := 20 * time.Millisecond
	started := make(chan struct{})
	c := func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		time.Sleep(50 * timeout)
		return nil
	}

	errCh := launch(
		[]app.Component{c},
		app.WithContext(ctx),
		app.WithTimeout(timeout),
	)

	await(t, started, "component start")
	cancel()

	err := result(t, errCh, "shutdown")
	if !errors.Is(err, app.ErrShutdownTimeout) {
		t.Errorf("got %v; want %v", err, app.ErrShutdownTimeout)
	}
}

func TestRun_WithLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	c := func(ctx context.Context) error {
		app.Logger(ctx).Info("Component logging")
		return nil
	}

	if err := app.Run(c, app.WithLogger(logger)); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	logs := buf.String()
	tests := []struct {
		name string
		want string
	}{
		{"log started", "Application starting"},
		{"log component", "Component logging"},
		{"log stopped", "Shutdown complete"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(logs, tt.want) {
				t.Errorf("want match for %q; got %q", tt.want, logs)
			}
		})
	}
}

// A component that returns nil has completed its work; it must not bring down
// the components running alongside it.
func TestRunAll_CleanExitKeepsOthersRunning(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	oneShot := func(context.Context) error { return nil }

	var canceled bool
	started := make(chan struct{})
	worker := func(ctx context.Context) error {
		app.Ready(ctx)
		close(started)
		<-ctx.Done()
		canceled = true
		return nil
	}

	errCh := launch(
		[]app.Component{oneShot, worker},
		app.WithContext(ctx),
	)

	await(t, started, "worker start")

	// The one-shot component has long returned. If it had triggered a
	// shutdown, the runner would already be done.
	select {
	case err := <-errCh:
		t.Fatalf("should still be running; returned %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()

	if err := result(t, errCh, "shutdown"); err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}

	if !canceled {
		t.Error("canceled: got false; want true")
	}
}

// Once every component has returned, there is nothing left to do.
func TestRunAll_StopsWhenAllComponentsExit(t *testing.T) {
	t.Parallel()

	quick := func(context.Context) error { return nil }
	slow := func(context.Context) error {
		time.Sleep(20 * time.Millisecond)
		return nil
	}

	errCh := launch([]app.Component{quick, slow})

	if err := result(t, errCh, "shutdown"); err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}
}

func TestRunAll_CascadingError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("worker failed")
	failing := func(context.Context) error { return wantErr }

	var canceled bool
	worker := func(ctx context.Context) error {
		<-ctx.Done()
		canceled = errors.Is(ctx.Err(), context.Canceled)
		return nil
	}

	err := app.RunAll([]app.Component{failing, worker})
	if !errors.Is(err, wantErr) {
		t.Errorf("error: got %v; want %v", err, wantErr)
	}

	if !canceled {
		t.Error("canceled: got false; want true")
	}
}

func TestRunAll_CascadingPanic(t *testing.T) {
	t.Parallel()

	var canceled bool
	panicking := func(context.Context) error { panic("worker panicked") }
	worker := func(ctx context.Context) error {
		<-ctx.Done()
		canceled = errors.Is(ctx.Err(), context.Canceled)
		return nil
	}

	err := app.RunAll([]app.Component{panicking, worker})

	if _, ok := errors.AsType[*app.PanicError](err); !ok {
		t.Errorf("error: got %v; want *app.PanicError", err)
	}

	if !canceled {
		t.Error("canceled: got false; want true")
	}
}

// Every failure must be reported, not just the one that happened to be
// observed first.
func TestRunAll_CollectsAllErrors(t *testing.T) {
	t.Parallel()

	errFirst := errors.New("first failure")
	errSecond := errors.New("second failure")

	first := func(context.Context) error { return errFirst }
	second := func(ctx context.Context) error {
		<-ctx.Done()
		return errSecond
	}

	err := app.RunAll([]app.Component{first, second})

	if !errors.Is(err, errFirst) {
		t.Errorf("first error: got %v; want %v", err, errFirst)
	}

	if !errors.Is(err, errSecond) {
		t.Errorf("second error: got %v; want %v", err, errSecond)
	}
}

// A component that fails during shutdown must not be masked by a sibling that
// exited cleanly beforehand.
func TestRunAll_ReportsErrorAfterCleanExit(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	wantErr := errors.New("drain failed")
	started := make(chan struct{})

	oneShot := func(context.Context) error { return nil }
	worker := func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return wantErr
	}

	errCh := launch(
		[]app.Component{oneShot, worker},
		app.WithContext(ctx),
	)

	await(t, started, "worker start")
	cancel()

	err := result(t, errCh, "shutdown")
	if !errors.Is(err, wantErr) {
		t.Errorf("got %v; want %v", err, wantErr)
	}
}

func TestRunAll_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		components []app.Component
		want       error
	}{
		{"nil slice", nil, app.ErrNoComponents},
		{"empty slice", []app.Component{}, app.ErrNoComponents},
		{
			"nil component",
			[]app.Component{func(context.Context) error { return nil }, nil},
			app.ErrNilComponent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := app.RunAll(tt.components)
			if !errors.Is(err, tt.want) {
				t.Errorf("got %v; want %v", err, tt.want)
			}
		})
	}
}

// Signal tests must not run in parallel: signals are delivered to the whole
// process, so concurrent runners would observe each other's interrupts.
func TestRun_SignalShutdown(t *testing.T) {
	cleaned := make(chan struct{})
	started := make(chan struct{})

	c := func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		close(cleaned)
		return nil
	}

	errCh := launch([]app.Component{c}, app.WithSignals(syscall.SIGUSR1))

	await(t, started, "component start")
	interrupt(t, syscall.SIGUSR1)

	if err := result(t, errCh, "shutdown"); err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}

	await(t, cleaned, "cleanup")
}

func TestRunAll_SignalShutdownAll(t *testing.T) {
	var mu sync.Mutex
	canceled := 0

	start := make([]chan struct{}, 2)
	components := make([]app.Component, 2)
	for i := range components {
		start[i] = make(chan struct{})
		components[i] = func(ctx context.Context) error {
			close(start[i])
			<-ctx.Done()
			mu.Lock()
			canceled++
			mu.Unlock()
			return nil
		}
	}

	errCh := launch(components, app.WithSignals(syscall.SIGUSR1))

	for i := range start {
		await(t, start[i], "component start")
	}
	interrupt(t, syscall.SIGUSR1)

	if err := result(t, errCh, "shutdown"); err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}

	if canceled != len(components) {
		t.Errorf("canceled: got %d; want %d", canceled, len(components))
	}
}

// Passing no signals disables signal handling, leaving the default
// disposition in place.
func TestRun_WithoutSignals(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Ignoring the signal process-wide keeps the default disposition from
	// killing the test binary once the runner declines to trap it.
	signal.Ignore(syscall.SIGUSR1)
	defer signal.Reset(syscall.SIGUSR1)

	started := make(chan struct{})
	errCh := launch(
		[]app.Component{blocked(started)},
		app.WithContext(ctx),
		app.WithSignals(),
	)

	await(t, started, "component start")
	interrupt(t, syscall.SIGUSR1)

	select {
	case err := <-errCh:
		t.Fatalf("should still be running; returned %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()

	if err := result(t, errCh, "shutdown"); err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}
}

func TestOptions_IgnoreInvalidValues(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	var (
		gotTimeout time.Duration
		gotLogger  *slog.Logger
	)

	c := func(ctx context.Context) error {
		gotTimeout = app.ShutdownTimeout(ctx)
		gotLogger = app.Logger(ctx)
		return nil
	}

	err := app.Run(c,
		app.WithLogger(logger),
		app.WithLogger(nil),
		app.WithTimeout(0),
		app.WithTimeout(-time.Second),
		app.WithStartTimeout(0),
		app.WithContext(nil),
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if gotTimeout != app.DefaultTimeout {
		t.Errorf("timeout: got %v; want %v", gotTimeout, app.DefaultTimeout)
	}

	if gotLogger != logger {
		t.Error("logger: got the default logger; want the configured one")
	}
}

func TestRunStages_WaitsForReadiness(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var mu sync.Mutex
	var order []string

	record := func(event string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, event)
	}

	ready := make(chan struct{})
	first := func(ctx context.Context) error {
		record("first started")
		// Simulate slow startup work. The second stage must not start yet.
		time.Sleep(50 * time.Millisecond)
		record("first ready")
		app.Ready(ctx)
		close(ready)
		<-ctx.Done()
		return nil
	}

	started := make(chan struct{})
	second := func(ctx context.Context) error {
		record("second started")
		close(started)
		<-ctx.Done()
		return nil
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.RunStages(
			[]app.Stage{{first}, {second}},
			app.WithContext(ctx),
		)
	}()

	await(t, ready, "first stage readiness")
	await(t, started, "second stage start")
	cancel()

	if err := result(t, errCh, "shutdown"); err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}

	want := []string{"first started", "first ready", "second started"}
	mu.Lock()
	defer mu.Unlock()

	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("order: got %v; want %v", order, want)
	}
}

func TestRunStages_ReverseShutdown(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var order []string

	stop := func(name string) app.Component {
		return func(ctx context.Context) error {
			app.Ready(ctx)
			<-ctx.Done()
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			return nil
		}
	}

	// A component in the final stage triggers the shutdown once the earlier
	// stages are up.
	wantErr := errors.New("service failed")
	trigger := func(ctx context.Context) error {
		app.Ready(ctx)
		return wantErr
	}

	err := app.RunStages([]app.Stage{
		{stop("database")},
		{stop("cache")},
		{trigger},
	})

	if !errors.Is(err, wantErr) {
		t.Errorf("error: got %v; want %v", err, wantErr)
	}

	want := []string{"cache", "database"}
	mu.Lock()
	defer mu.Unlock()

	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("shutdown order: got %v; want %v", order, want)
	}
}

func TestRunStages_StartTimeout(t *testing.T) {
	t.Parallel()

	var started bool
	stuck := func(ctx context.Context) error {
		// Never signals readiness.
		<-ctx.Done()
		return nil
	}
	next := func(ctx context.Context) error {
		started = true
		<-ctx.Done()
		return nil
	}

	err := app.RunStages(
		[]app.Stage{{stuck}, {next}},
		app.WithStartTimeout(20*time.Millisecond),
	)

	if !errors.Is(err, app.ErrStartTimeout) {
		t.Errorf("error: got %v; want %v", err, app.ErrStartTimeout)
	}

	if started {
		t.Error("second stage started: got true; want false")
	}
}

// A stage whose components all return is ready, so one-shot work such as a
// migration need not signal readiness explicitly.
func TestRunStages_ReturnImpliesReadiness(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	migrate := func(context.Context) error { return nil }
	started := make(chan struct{})

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.RunStages(
			[]app.Stage{{migrate}, {blocked(started)}},
			app.WithContext(ctx),
			app.WithStartTimeout(settle),
		)
	}()

	await(t, started, "second stage start")
	cancel()

	if err := result(t, errCh, "shutdown"); err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}
}

func TestRunStages_Validation(t *testing.T) {
	t.Parallel()

	if err := app.RunStages(nil); !errors.Is(err, app.ErrNoComponents) {
		t.Errorf("got %v; want %v", err, app.ErrNoComponents)
	}
}
