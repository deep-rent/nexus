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

package postgres

import (
	"context"
	"log/slog"
	"time"

	"github.com/deep-rent/nexus/log"
)

// Default retention windows enforced by [Retention].
const (
	// DefaultMutationRetention is the default age above which mutation
	// deduplication records are pruned.
	DefaultMutationRetention = 30 * 24 * time.Hour
	// DefaultTombstoneRetention is the default age above which tombstones
	// are pruned, advancing the retention floor.
	DefaultTombstoneRetention = 90 * 24 * time.Hour
)

// RetentionOption configures a [Retention] task.
type RetentionOption func(*Retention)

// WithMutationRetention overrides [DefaultMutationRetention]. The window
// bounds idempotent deduplication: a client replaying a change set older
// than the window re-applies it. This is harmless to state (last-write-wins
// skips equal timestamps on upserts and deletes alike), so the window
// merely needs to exceed the longest realistic retry horizon.
//
// Non-positive values are ignored.
func WithMutationRetention(d time.Duration) RetentionOption {
	return func(r *Retention) {
		if d > 0 {
			r.mutations = d
		}
	}
}

// WithTombstoneRetention overrides [DefaultTombstoneRetention]. The window
// bounds how long a device may stay offline without losing its cursor:
// pruning advances the retention floor, and clients whose cursor predates
// it are forced into a full resync from zero.
//
// Non-positive values are ignored.
func WithTombstoneRetention(d time.Duration) RetentionOption {
	return func(r *Retention) {
		if d > 0 {
			r.tombstones = d
		}
	}
}

// Retention is a ready-made maintenance task enforcing the store's two
// retention windows: it prunes aged mutation deduplication records
// ([Store.PruneMutations]) and aged tombstones ([Store.PruneTombstones]),
// logging the outcome through the store's logger. Failures are logged and
// swallowed; the next run retries, so the task is safe to schedule
// fire-and-forget.
//
// Retention satisfies the Task contract of the schedule package, so wiring
// the maintenance loop is a single dispatch:
//
//	s := schedule.New(ctx)
//	defer s.Shutdown()
//	s.Dispatch(schedule.Every(time.Hour, postgres.NewRetention(store)))
//
// Runs are idempotent and cheap when there is nothing to prune; an hourly
// cadence is plenty for the default windows. In multi-replica deployments,
// schedule it on every replica or one — concurrent runs are safe, merely
// redundant.
type Retention struct {
	store      *Store
	mutations  time.Duration
	tombstones time.Duration
}

// NewRetention creates a retention task around the given store. It panics
// if the store is nil (programmer error).
func NewRetention(s *Store, opts ...RetentionOption) *Retention {
	if s == nil {
		panic("store is required")
	}
	r := &Retention{
		store:      s,
		mutations:  DefaultMutationRetention,
		tombstones: DefaultTombstoneRetention,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Run executes one maintenance pass. A failing prune is logged and does not
// prevent the other from running.
func (r *Retention) Run(ctx context.Context) {
	logger := r.store.logger
	if n, err := r.store.PruneMutations(ctx, r.mutations); err != nil {
		logger.Error("Failed to prune mutations", log.Err(err))
	} else if n > 0 {
		logger.Info("Pruned aged mutations", slog.Int64("count", n))
	}
	if n, err := r.store.PruneTombstones(ctx, r.tombstones); err != nil {
		logger.Error("Failed to prune tombstones", log.Err(err))
	} else if n > 0 {
		logger.Info("Pruned aged tombstones", slog.Int64("count", n))
	}
}
