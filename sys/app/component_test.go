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
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/sys/app"
	"github.com/deep-rent/nexus/sys/log"
)

func TestLogger_Default(t *testing.T) {
	t.Parallel()

	if got := app.Logger(t.Context()); got != log.Discard() {
		t.Error("got a custom logger; want the discard logger")
	}
}

func TestShutdownTimeout_Default(t *testing.T) {
	t.Parallel()

	got := app.ShutdownTimeout(t.Context())
	if got != app.DefaultTimeout {
		t.Errorf("got %v; want %v", got, app.DefaultTimeout)
	}
}

func TestReady_OutsideRunner(t *testing.T) {
	t.Parallel()

	// Must not panic on a context that carries no readiness signal.
	app.Ready(t.Context())
}

func TestNamed_WrapsError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("an error")
	c := app.Named("worker", func(context.Context) error { return wantErr })

	err := c(t.Context())

	var componentErr *app.ComponentError
	if !errors.As(err, &componentErr) {
		t.Fatalf("error: got %T; want *app.ComponentError", err)
	}

	if got := componentErr.Name; got != "worker" {
		t.Errorf("name: got %q; want %q", got, "worker")
	}

	if !errors.Is(err, wantErr) {
		t.Errorf("error: got %v; want %v", err, wantErr)
	}

	if want := `component "worker"`; !strings.Contains(err.Error(), want) {
		t.Errorf("message: want match for %q; got %q", want, err.Error())
	}
}

func TestNamed_WrapsPanic(t *testing.T) {
	t.Parallel()

	c := app.Named("worker", func(context.Context) error { panic("boom") })

	err := c(t.Context())

	if _, ok := errors.AsType[*app.ComponentError](err); !ok {
		t.Fatalf("error: got %T; want *app.ComponentError", err)
	}

	var panicErr *app.PanicError
	if !errors.As(err, &panicErr) {
		t.Fatalf("error: got %v; want a wrapped *app.PanicError", err)
	}

	if got := panicErr.Value; got != "boom" {
		t.Errorf("panic value: got %v; want %q", got, "boom")
	}
}

func TestNamed_PassesNil(t *testing.T) {
	t.Parallel()

	c := app.Named("worker", func(context.Context) error { return nil })

	if err := c(t.Context()); err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}
}

func TestNamed_ScopesLogger(t *testing.T) {
	t.Parallel()

	rec := log.NewRecorder()
	logger := log.Wrap(rec)

	c := app.Named("worker", func(ctx context.Context) error {
		app.Logger(ctx).Info(ctx, "hello")
		return nil
	})

	if err := app.Run(c, app.WithLogger(logger)); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	for _, r := range rec.Records() {
		if r.Msg != "hello" {
			continue
		}
		for _, arg := range r.Args {
			if arg.Key == "component" && arg.Value() == "worker" {
				return
			}
		}
		t.Fatalf("record %q lacks component=worker: %v", r.Msg, r.Args)
	}
	t.Error("no record with message \"hello\" was captured")
}

func TestGraceful_StopsOnCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())

	var (
		stopped  bool
		liveCtx  bool
		deadline bool
	)

	c := app.Graceful(
		func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		},
		func(ctx context.Context) error {
			stopped = true
			// The stop context must not inherit the cancellation.
			liveCtx = ctx.Err() == nil
			_, deadline = ctx.Deadline()
			return nil
		},
	)

	cancel()

	if err := c(ctx); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if !stopped {
		t.Error("stopped: got false; want true")
	}

	if !liveCtx {
		t.Error("stop context: got canceled; want live")
	}

	if !deadline {
		t.Error("stop context: got no deadline; want one")
	}
}

func TestGraceful_SkipsStopOnEarlyReturn(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("an error")
	var stopped bool

	c := app.Graceful(
		func(context.Context) error { return wantErr },
		func(context.Context) error {
			stopped = true
			return nil
		},
	)

	if err := c(t.Context()); !errors.Is(err, wantErr) {
		t.Errorf("error: got %v; want %v", err, wantErr)
	}

	if stopped {
		t.Error("stopped: got true; want false")
	}
}

func TestGraceful_ReportsStopError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	wantErr := errors.New("drain failed")
	c := app.Graceful(
		func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		},
		func(context.Context) error { return wantErr },
	)

	if err := c(ctx); !errors.Is(err, wantErr) {
		t.Errorf("error: got %v; want %v", err, wantErr)
	}
}

func TestGraceful_RecoversPanic(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	c := app.Graceful(
		func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		},
		func(context.Context) error { panic("boom") },
	)

	err := c(ctx)

	if _, ok := errors.AsType[*app.PanicError](err); !ok {
		t.Fatalf("error: got %v; want *app.PanicError", err)
	}
}

// A start function that ignores its context must not block the runner past the
// shutdown budget.
func TestGraceful_StartTimeout(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	defer close(release)

	c := app.Graceful(
		func(context.Context) error {
			<-release
			return nil
		},
		func(context.Context) error { return nil },
	)

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.Run(c,
			app.WithContext(canceled(t)),
			app.WithTimeout(20*time.Millisecond),
		)
	}()

	err := result(t, errCh, "shutdown")
	if !errors.Is(err, app.ErrShutdownTimeout) {
		t.Errorf("error: got %v; want %v", err, app.ErrShutdownTimeout)
	}
}

func TestSequence_RunsInOrder(t *testing.T) {
	t.Parallel()

	var order []string
	step := func(name string) app.Component {
		return func(context.Context) error {
			order = append(order, name)
			return nil
		}
	}

	c := app.Sequence(step("first"), step("second"), step("third"))

	if err := c(t.Context()); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if want := "first,second,third"; strings.Join(order, ",") != want {
		t.Errorf("order: got %v; want %v", order, want)
	}
}

func TestSequence_StopsOnError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("an error")
	var reached bool

	c := app.Sequence(
		func(context.Context) error { return wantErr },
		func(context.Context) error {
			reached = true
			return nil
		},
	)

	if err := c(t.Context()); !errors.Is(err, wantErr) {
		t.Errorf("error: got %v; want %v", err, wantErr)
	}

	if reached {
		t.Error("second step reached: got true; want false")
	}
}

func TestSequence_StopsOnCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	var reached bool

	c := app.Sequence(
		func(context.Context) error {
			cancel()
			return nil
		},
		func(context.Context) error {
			reached = true
			return nil
		},
	)

	if err := c(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("error: got %v; want %v", err, context.Canceled)
	}

	if reached {
		t.Error("second step reached: got true; want false")
	}
}

func TestSequence_RejectsNil(t *testing.T) {
	t.Parallel()

	c := app.Sequence(nil)

	if err := c(t.Context()); !errors.Is(err, app.ErrNilComponent) {
		t.Errorf("error: got %v; want %v", err, app.ErrNilComponent)
	}
}

// canceled returns a context that is already canceled.
func canceled(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	return ctx
}
