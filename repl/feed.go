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
	"fmt"

	"github.com/deep-rent/nexus/internal/graph"
)

type Delta struct {
	// Entity is the type of entity affected.
	Entity Entity `json:"entity"`
	// Delete is the list of entity IDs that were deleted.
	Delete []UUID `json:"delete"`
	// Update is the list of complete entity states that were updated.
	Update any `json:"update"`
}

type Feed struct {
	// Time is the new HLC anchor after applying the diff.
	Time uint64 `json:"time"`
	// Diff is the set of changes in order of application.
	Diff []Delta `json:"diff"`
}

// Feeder coordinates the generation of the outbound synchronization Feed.
type Feeder[Tx any] struct {
	store   Store[Tx]
	graph   *graph.Graph[Entity]
	readers map[Entity]Reader[Tx]
	hlc     func() uint64 // Function to get current HLC time
}

// NewFeeder initializes a new Feed generator.
func NewFeeder[Tx any](store Store[Tx], hlc func() uint64) *Feeder[Tx] {
	return &Feeder[Tx]{
		store:   store,
		graph:   graph.New[Entity](),
		readers: make(map[Entity]Reader[Tx]),
		hlc:     hlc,
	}
}

// Register adds an entity reader to the feeder. The dependencies must
// represent parent entities that this entity depends on.
func (f *Feeder[Tx]) Register(r Reader[Tx], deps ...Entity) {
	entity := r.Entity()
	if _, exists := f.readers[entity]; exists {
		panic(fmt.Sprintf(
			"sync: fetcher already registered for entity %q",
			entity,
		))
	}

	f.readers[entity] = r
	f.graph.AddNode(entity)

	for _, parent := range deps {
		f.graph.AddEdge(entity, parent)
	}
}

// Build generates the complete synchronization payload for a client that last
// synced at the given timestamp.
func (f *Feeder[Tx]) Build(ctx context.Context, since uint64) (*Feed, error) {
	// 1. Get topological sort (parents first, then children)
	entities, err := f.graph.Sort()
	if err != nil {
		return nil, fmt.Errorf("sync: failed to sort entities: %w", err)
	}

	// 2. Determine the new time time for the client
	time := f.hlc()

	var diff []Delta

	// 3. Open a read-only transaction (represented by store.Exec)
	if err := f.store.Exec(ctx, func(ctx context.Context, tx Tx) error {
		// We collect the fetched data so we only query once per entity
		delete := make(map[Entity][]UUID)
		update := make(map[Entity]any)

		for _, entity := range entities {
			r, exists := f.readers[entity]
			if !exists {
				// The entity might be purely a structural node in the DAG
				// without a reader, though normally it should have one.
				continue
			}

			upd, del, err := r.Fetch(ctx, tx, since)
			if err != nil {
				return fmt.Errorf("failed to fetch %q: %w", entity, err)
			}

			if len(del) > 0 {
				delete[entity] = del
			}
			// We check if updates is not nil (as any)
			if upd != nil {
				update[entity] = upd
			}
		}

		// Phase 1: Deletes must be applied bottom-up (children first).
		// We iterate the sorted list in reverse order.
		for i := len(entities) - 1; i >= 0; i-- {
			entity := entities[i]
			if deletes, ok := delete[entity]; ok {
				diff = append(diff, Delta{
					Entity: entity,
					Delete: deletes,
					Update: nil,
				})
			}
		}

		// Phase 2: Updates must be applied top-down (parents first).
		// We iterate the sorted list in forward order.
		for _, entity := range entities {
			if updates, ok := update[entity]; ok {
				diff = append(diff, Delta{
					Entity: entity,
					Delete: nil,
					Update: updates,
				})
			}
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return &Feed{
		Time: time,
		Diff: diff,
	}, nil
}
