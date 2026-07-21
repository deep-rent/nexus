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

// Package mock provides an in-memory implementation of the migrate.Driver.
//
// It is designed strictly for unit testing: the driver is safe for concurrent
// use and allows injecting errors for every operation to test the Migrator's
// error handling and rollback logic.
//
// # Usage
//
// Create a new mock driver and use its exported fields to assert that specific
// database operations (like locking or initialization) were performed by the
// migrator.
//
// Example:
//
//	drv := mock.New()
//	m := migrate.New(migrate.WithDriver(drv), migrate.WithSource(src))
//	_ = m.Up(ctx)
//
//	if !drv.IsInit {
//	    t.Error("expected driver to be initialized")
//	}
package mock
