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

package app

import (
	"context"
	"errors"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

// Component defines a function that can be executed by the application runner.
// It receives a [context.Context] that is canceled once the application starts
// to shut down. The function is expected to return promptly after its context
// is done.
//
// A component that returns nil is considered to have completed its work. It
// does not cause the application to shut down; the remaining components keep
// running. A component that returns a non-nil error, or panics, triggers a
// graceful shutdown of the entire application.
type Component func(ctx context.Context) error

type (
	loggerKey  struct{}
	timeoutKey struct{}
	readyKey   struct{}
)

// Logger returns the [slog.Logger] configured on the runner via [WithLogger].
// It returns [slog.Default] if ctx does not originate from a runner. Prefer
// this over a package-level logger so that component output is correlated with
// the application lifecycle. See also [Named].
func Logger(ctx context.Context) *slog.Logger {
	if log, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && log != nil {
		return log
	}
	return slog.Default()
}

// ShutdownTimeout returns the graceful shutdown budget configured on the
// runner via [WithTimeout]. It returns [DefaultTimeout] if ctx does not
// originate from a runner.
//
// Components that need to perform blocking cleanup after their context is
// canceled should bound it by this duration, typically by deriving a fresh
// context via [context.WithoutCancel]. See [Graceful], which does this for
// you.
func ShutdownTimeout(ctx context.Context) time.Duration {
	if d, ok := ctx.Value(timeoutKey{}).(time.Duration); ok && d > 0 {
		return d
	}
	return DefaultTimeout
}

// Ready signals that the [Component] associated with ctx has finished its
// startup work and that dependent components may now be started. It is safe to
// call Ready multiple times, from multiple goroutines, or on a context that
// does not originate from a runner, in which case it does nothing.
//
// Ready is only meaningful for components running in a non-final [Stage]; see
// [RunStages]. Every component in such a stage must eventually call Ready or
// return, otherwise startup fails with [ErrStartTimeout]. Returning implies
// readiness, so one-shot components such as schema migrations need not call
// Ready explicitly.
func Ready(ctx context.Context) {
	if signal, ok := ctx.Value(readyKey{}).(func()); ok {
		signal()
	}
}

// Named returns a [Component] that behaves like c, but attributes any error or
// panic it produces to name via [ComponentError], and scopes the logger
// returned by [Logger] with a "component" attribute. Naming components is
// recommended: without it, an error surfacing from a multi-component
// application carries no indication of its origin.
func Named(name string, c Component) Component {
	if c == nil {
		panic("app: Named requires a non-nil component")
	}
	return func(ctx context.Context) error {
		log := Logger(ctx).With(slog.String("component", name))
		ctx = context.WithValue(ctx, loggerKey{}, log)
		if err := invoke(ctx, c); err != nil {
			return &ComponentError{Name: name, Err: err}
		}
		return nil
	}
}

// Graceful returns a [Component] that runs start and, once the component's
// context is canceled, invokes stop to release resources.
//
// Unlike the context handed to start, the context handed to stop is not
// canceled; it carries a fresh deadline derived from [ShutdownTimeout]. This
// makes Graceful the natural adapter for resources whose teardown is itself
// context-aware, such as [net/http.Server.Shutdown] or a database pool drain.
//
// If start returns before the context is canceled, stop is not invoked. Server
// implementations that report their own closure as an error should normalize
// it, for example:
//
//	app.Graceful(
//	  func(ctx context.Context) error {
//	    app.Ready(ctx)
//	    err := srv.ListenAndServe()
//	    if errors.Is(err, http.ErrServerClosed) {
//	      return nil
//	    }
//	    return err
//	  },
//	  srv.Shutdown,
//	)
//
// Graceful panics if start or stop is nil.
func Graceful(start Component, stop func(ctx context.Context) error) Component {
	if start == nil || stop == nil {
		panic("requires non-nil start and stop functions")
	}
	return func(ctx context.Context) error {
		errCh := make(chan error, 1)
		go func() { errCh <- invoke(ctx, start) }()

		select {
		case err := <-errCh:
			// The component finished on its own; there is nothing to stop.
			return err
		case <-ctx.Done():
		}

		// Detach from the canceled context so that stop can still perform
		// blocking work, but bound it by the shutdown budget.
		stopCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			ShutdownTimeout(ctx),
		)
		defer cancel()

		stopErr := invoke(stopCtx, stop)

		var startErr error
		select {
		case startErr = <-errCh:
		case <-stopCtx.Done():
			startErr = errors.Join(
				ErrShutdownTimeout,
				errors.New("start did not return after stop"),
			)
		}

		return errors.Join(startErr, stopErr)
	}
}

// Sequence returns a [Component] that invokes the given components one after
// another, stopping at the first error. It is intended for ordered one-shot
// work, such as running migrations before seeding data. Long-running
// components should be ordered with [RunStages] instead, since they never
// return on their own.
func Sequence(components ...Component) Component {
	return func(ctx context.Context) error {
		for _, c := range components {
			if c == nil {
				return ErrNilComponent
			}
			if err := invoke(ctx, c); err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		return nil
	}
}

// invoke calls c, converting a panic into a [PanicError]. Nested calls are
// harmless: the innermost recovery wins, which keeps the stack trace close to
// the origin of the panic.
func invoke(ctx context.Context, c Component) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &PanicError{Value: r, Stack: debug.Stack()}
		}
	}()
	return c(ctx)
}

// once returns a function that runs fn at most once. It is used to build the
// idempotent readiness signal handed to each component.
func once(fn func()) func() {
	var o sync.Once
	return func() { o.Do(fn) }
}
