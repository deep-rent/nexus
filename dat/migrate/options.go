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

package migrate

import (
	"github.com/deep-rent/nexus/sys/log"
)

// Option configures a [Migrator] instance.
type Option func(*Migrator)

// WithSource sets the migration source.
//
// This option is mandatory.
func WithSource(source Source) Option {
	return func(m *Migrator) {
		m.source = source
	}
}

// WithDriver sets the database driver.
//
// This option is mandatory.
func WithDriver(driver Driver) Option {
	return func(m *Migrator) {
		m.driver = driver
	}
}

// WithDryRun enables a mode where the [Migrator] computes checksums and logs.
//
// It logs the parsed statements without executing them against the database.
func WithDryRun(enabled bool) Option {
	return func(m *Migrator) {
		m.dryRun = enabled
	}
}

// WithStrictOrder makes the [Migrator] reject out-of-order migrations.
//
// When enabled, applying a pending migration whose version is lower than the
// highest already-applied version returns an error instead of silently
// executing it after its successors. Such gaps typically appear when branches
// with independently numbered migrations are merged. The default is lenient:
// out-of-order migrations are applied in ascending version order.
func WithStrictOrder(enabled bool) Option {
	return func(m *Migrator) {
		m.strict = enabled
	}
}

// WithLogger sets the logger for the migrator.
//
// A nil value will be ignored.
func WithLogger(logger *log.Logger) Option {
	return func(m *Migrator) {
		if logger != nil {
			m.logger = logger
		}
	}
}
