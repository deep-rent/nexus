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

// Package app provides a managed lifecycle for long-running applications such
// as servers, workers and daemons, ensuring graceful shutdown on OS signals.
//
// [Run], [RunAll] and [RunStages] are the entry points. They execute your
// application [Component] functions, listen for interrupt signals, and
// propagate cancellation so that every component can clean up before the
// process exits.
//
// # Shutdown
//
// A shutdown is triggered by any of the following:
//
//   - an OS signal, by default [syscall.SIGINT] or [syscall.SIGTERM],
//   - cancellation of the parent context passed to [WithContext],
//   - a [Component] returning a non-nil error or panicking,
//   - all components having returned.
//
// A component that returns nil is considered done, not fatal: the remaining
// components keep running. This makes it safe to mix one-shot work, such as
// schema migrations, with components that run for the lifetime of the process.
//
// Once shutdown begins, component contexts are canceled and the runner waits
// up to the timeout set by [WithTimeout]. Errors from all components are
// collected and returned as a single joined error; errors that wrap
// [context.Canceled] are discarded, since they are the expected result of
// cancellation.
//
// The runner restores the default OS signal disposition as soon as shutdown
// begins, so a second interrupt terminates the process immediately rather than
// waiting for a stuck component.
//
// # Startup order
//
// [RunStages] starts components in ordered stages. All components of a stage
// run concurrently, but a stage is only started once every component of the
// preceding stage has signalled readiness via [Ready] or has returned. On
// shutdown, stages are stopped in reverse order, so dependencies outlive their
// dependents.
//
// # Usage
//
// A typical application starts a background worker alongside a server:
//
//	func main() {
//	  logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
//
//	  worker := func(ctx context.Context) error {
//	    ticker := time.NewTicker(time.Second)
//	    defer ticker.Stop()
//	    for {
//	      select {
//	      case <-ctx.Done():
//	        return nil
//	      case <-ticker.C:
//	        app.Logger(ctx).Info("Working...")
//	      }
//	    }
//	  }
//
//	  srv := &http.Server{Addr: ":8080"}
//	  server := app.Graceful(
//	    func(ctx context.Context) error {
//	      app.Ready(ctx)
//	      err := srv.ListenAndServe()
//	      if errors.Is(err, http.ErrServerClosed) {
//	        return nil
//	      }
//	      return err
//	    },
//	    srv.Shutdown,
//	  )
//
//	  err := app.RunAll(
//	    []app.Component{
//	      app.Named("worker", worker),
//	      app.Named("server", server),
//	    },
//	    app.WithLogger(logger),
//	  )
//	  if err != nil {
//	    logger.Error("Application failed", log.Err(err))
//	    os.Exit(1)
//	  }
//	}
package app
