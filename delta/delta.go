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

package delta

import (
	"context"
	"encoding/json/jsontext"

	"github.com/deep-rent/nexus/internal/hlc"
	"github.com/deep-rent/nexus/uuid"
)

type Action string

const (
	Create Action = "create"
	Update Action = "update"
	Delete Action = "delete"
)

// EntityType defines the type of entity that is being synchronized.
// It usually relates to a resource collection such as a database table, a
// view, or a queue.
type EntityType string

// ChangeType defines the type of change that is being synchronized.
type ChangeType struct {
	// Action specifies the type of change to apply.
	Action Action `json:"action"`
	// EntityType specifies the type of entity to apply the change to.
	EntityType EntityType `json:"entity_type"`
	// Version is the version of the change payload, starting at zero. Multiple
	// versions may exist for the same action and entity combination to support
	// backwards compatibility on schema updates.
	Version uint64 `json:"version"`
}

// Change envelops a single granular change to the state.
type Change struct {
	// ID is the idempotency identifier, used to deduplicate changes.
	// The client assigns a random UUID to each change.
	ID uuid.UUID `json:"id"`
	// Type describes the target of the change and the format of the payload.
	Type ChangeType `json:",embed"`
	// EntityID is the unique identifier of the entity being changed within
	// the scope of the entity type.
	EntityID uuid.UUID `json:"entity_id"`
	// Data contains the fields that need to be set or unset.
	// For [Create] actions, this is the full entity; for [Update] actions a
	// partial payload is provided; for [Delete] actions it is usually empty.
	Data jsontext.Value `json:"data"`
	// Time is the HLC timestamp of the change event.
	Time hlc.Time `json:"time"`
}

// ChangeSet represents a batch of changes submitted for ingestion.
type ChangeSet struct {
	// Changes is the list of changes in order of occurrence on the producer
	// side (oldest to newest).
	Changes []Change `json:"changes"`
	// OwnerID is the ID of the subject publishing the changes.
	// It is used to enforce access control and for accountability.
	OwnerID uuid.UUID `json:"owner_id"`
}

// Ingester manages the inbound synchronization pipeline into the [State].
type Ingester interface {
	Supported() []ChangeType

	Ingest(ctx context.Context, set *ChangeSet) error
}

type Patch struct {
	// EntityType is the type of entity affected by the patch.
	EntityType EntityType `json:"entity_type"`
	// Deletes is the list of entity IDs that were deleted.
	Deletes []uuid.UUID `json:"deletes,omitempty"`
	// Updates is the list of complete entity states that were updated.
	Updates any `json:"updates,omitempty"`
}

type Feed struct {
	// Patches is the list of modifications in order of application.
	// Each patch concerns a specific entity type.
	Patches []Patch `json:"patches"`
	// Time is the new anchor to store after applying the patches.
	Time hlc.Time `json:"time"`
	// More indicates if there are more patches available following the returned
	// timestamp.
	More bool `json:"more"`
}

type FeedRequest struct {
	// OwnerID is the ID of the subject requesting the feed.
	// It is used to enforce access control and for accountability.
	OwnerID uuid.UUID `json:"owner_id"`
	// Since is the timestamp from which to start collecting patches.
	Since hlc.Time `json:"since"`
	// Until is used for subsequent page requests. If present and positive, it
	// serves as the upper bound for the feed sync.
	Until hlc.Time `json:"until"`
	// EntityTypes is the set of entity types to collect patches for.
	// If empty, all entity types are collected.
	EntityTypes []EntityType `json:"entity_types"`
	// Limit caps the number of atomic records returned in the feed.
	// If zero, a system-default maximum is applied.
	Limit uint32 `json:"limit"`
}

// Feeder coordinates the generation of the outbound synchronization [Feed] from
// the [State].
type Feeder interface {
	Supported() []EntityType

	Feed(ctx context.Context, req FeedRequest) (*Feed, error)
}

// State abstracts the execution of transactions against a durable store.
type State[Tx any] interface {
	// Exec executes a callback within a transaction.
	Exec(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error
}

// Deduplicator defines a two-phase commit contract for filtering duplicate
// [Change] events.
type Deduplicator interface {
	// Lock attempts to acquire an idempotency lease on the set of change IDs.
	// It returns the subset of IDs that were successfully locked (i.e. are
	// actually new).
	Lock(ctx context.Context, ids []uuid.UUID) ([]uuid.UUID, error)

	// Commit marks the given change IDs as permanently processed.
	Commit(ctx context.Context, ids []uuid.UUID) error

	// Unlock releases the pending locks for the given IDs if a transaction
	// fails (i.e. is rolled back)
	Unlock(ctx context.Context, ids []uuid.UUID) error
}
