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

package repl

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"strconv"
)

type Action string

type Kind struct {
	// Action specifies the type of change to apply (e.g., "create", "update",
	// "delete", ...).
	Action Action
	// Entity specifies the type of entity to apply the change to (e.g.,
	// "user", "booking", "inquiry", ...).
	Entity Entity
	// Version is the version of the change payload, starting at zero. Multiple
	// versions may exist for the same action and entity combination to support
	// backwards compatibility on schema updates.
	Version uint64
}

func (k Kind) String() string {
	return string(k.Action) +
		"." + string(k.Entity) +
		"@" + strconv.FormatUint(k.Version, 10)
}

func NewKind(action Action, entity Entity, version uint64) Kind {
	return Kind{
		Action:  action,
		Entity:  entity,
		Version: version,
	}
}

// Change envelops a single granular change event.
type Change struct {
	// ChangeID is the idempotency identifier, used to deduplicate changes.
	// The client assigns a random UUID to each change.
	ChangeID UUID
	// EntityID is the unique identifier of the row being affected.
	EntityID UUID
	// Kind describes the target of the change and the format of the payload.
	Kind Kind
	// Time is the HLC timestamp of the change event.
	Time uint64
	// Payload contains only the fields that need to be set or unset.
	// For create actions, this is the full entity; for update actions a partial
	// payload is provided; for delete actions it is typically empty.
	Payload jsontext.Value
}

// Store abstracts the execution of a database transaction.
type Store[Tx any] interface {
	// Exec executes a callback within a transaction.
	Exec(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error
}

// Deduplicator defines a two-phase commit contract for filtering duplicate
// change events.
type Deduplicator interface {
	// Lock attempts to acquire an idempotency lease on the set of change IDs.
	// It returns the subset of IDs that were successfully locked (i.e. are
	// actually new).
	Lock(ctx context.Context, ids []UUID) ([]UUID, error)

	// Commit marks the given change IDs as permanently processed.
	Commit(ctx context.Context, ids []UUID) error

	// Unlock releases the pending locks for the given IDs if a transaction
	// fails (i.e. is rolled back)
	Unlock(ctx context.Context, ids []UUID) error
}

// Pipeline manages the synchronization pipeline.
type Pipeline[Tx any] struct {
	store Store[Tx]
	dedup Deduplicator
	procs map[Kind]Writer[Tx]
}

func NewPipeline[Tx any](store Store[Tx], dedup Deduplicator) *Pipeline[Tx] {
	return &Pipeline[Tx]{
		store: store,
		dedup: dedup,
		procs: make(map[Kind]Writer[Tx]),
	}
}

func (p *Pipeline[Tx]) Register(processor Writer[Tx]) {
	key := processor.Kind()
	if _, exists := p.procs[key]; exists {
		panic("sync: processor already registered for action: " + key.String())
	}
	p.procs[key] = processor
}

func (p *Pipeline[Tx]) Ingest(ctx context.Context, batch []Change) error {
	if len(batch) == 0 {
		return nil
	}

	all := make([]UUID, len(batch))
	for i, c := range batch {
		all[i] = c.ChangeID
	}

	locked, err := p.dedup.Lock(ctx, all)
	if err != nil {
		return err
	}
	if len(locked) == 0 {
		return nil
	}

	unique := make(map[UUID]struct{}, len(locked))
	for _, id := range locked {
		unique[id] = struct{}{}
	}

	if err := p.store.Exec(ctx, func(ctx context.Context, tx Tx) error {
		for _, c := range batch {
			if _, ok := unique[c.ChangeID]; !ok {
				continue
			}

			proc, ok := p.procs[c.Kind]
			if !ok {
				return fmt.Errorf("unknown change %s", c.Kind)
			}

			if err := proc.Handle(ctx, tx, c); err != nil {
				// Allow ignoring changes (e.g., server-side compaction)
				return fmt.Errorf("failed to apply change %q", c.ChangeID)
			}
		}

		return nil
	}); err != nil {
		return errors.Join(p.dedup.Unlock(ctx, locked), err)
	}

	if err := p.dedup.Commit(ctx, locked); err != nil {
		return err
	}

	return nil
}
