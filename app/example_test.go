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
	"net/http"
	"os"
	"time"

	"github.com/deep-rent/nexus/app"
)

// A component runs until its context is canceled. Returning nil marks it as
// done without stopping the components running alongside it.
func ExampleRunAll() {
	worker := func(ctx context.Context) error {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				app.Logger(ctx).Info("Working...")
			}
		}
	}

	migrate := func(ctx context.Context) error {
		app.Logger(ctx).Info("Migrating...")
		return nil // Done, but the worker keeps running.
	}

	err := app.RunAll([]app.Component{
		app.Named("migrate", migrate),
		app.Named("worker", worker),
	})
	if err != nil {
		os.Exit(1)
	}
}

// Graceful adapts resources whose teardown is context-aware, such as an HTTP
// server. The context passed to stop is not canceled; it carries a deadline
// derived from the shutdown timeout.
func ExampleGraceful() {
	srv := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 5 * time.Second,
	}

	server := app.Graceful(
		func(ctx context.Context) error {
			app.Ready(ctx)
			err := srv.ListenAndServe()
			if errors.Is(err, http.ErrServerClosed) {
				return nil // Expected once Shutdown is called.
			}
			return err
		},
		srv.Shutdown,
	)

	if err := app.Run(app.Named("server", server)); err != nil {
		os.Exit(1)
	}
}

// Stages express startup order. The server is only started once the database
// reports readiness, and on shutdown the database outlives the server.
func ExampleRunStages() {
	database := func(ctx context.Context) error {
		// Establish the pool, then release the components that depend on it.
		app.Ready(ctx)
		<-ctx.Done()
		return nil
	}

	server := func(ctx context.Context) error {
		app.Ready(ctx)
		<-ctx.Done()
		return nil
	}

	err := app.RunStages(
		[]app.Stage{
			{app.Named("database", database)},
			{app.Named("server", server)},
		},
		app.WithStartTimeout(15*time.Second),
		app.WithTimeout(30*time.Second),
	)
	if err != nil {
		os.Exit(1)
	}
}
