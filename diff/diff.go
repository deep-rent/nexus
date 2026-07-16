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

// The package overview, usage example, model narrative, and client
// contract live in doc.go.
package diff

import (
	"context"
	"encoding/json/jsontext"
	"slices"

	"uuid"

	"github.com/deep-rent/nexus/internal/hlc"
)

// Scope is the authorization boundary of a single sync call: the
// authenticated user and the teams they belong to. Identifiers are opaque
// strings taken from the verified token; payload identifiers are validated
// to be UUIDs at ingestion before they are compared against the scope.
type Scope struct {
	// UserID identifies the authenticated user.
	UserID string
	// Teams lists the identifiers of all teams the user is a member of.
	Teams []string
}

// Allows reports whether a document owned by userID and assigned to teamID
// (nil for personal documents) is directly accessible within the scope.
// Grant-based visibility of foreign personal documents is evaluated by the
// store, not here.
func (s Scope) Allows(userID string, teamID *string) bool {
	if userID == s.UserID {
		return true
	}
	return teamID != nil && slices.Contains(s.Teams, *teamID)
}

// Meta is the identifying envelope of a root document payload. Child
// documents carry only their ID; their ownership is inferred from the parent
// chain. User and team identifiers are strings, validated to be UUIDs at
// ingestion.
type Meta struct {
	// ID is the document identifier (UUIDv7).
	ID uuid.UUID `json:"id"`
	// UserID is the immutable owner of the document.
	UserID string `json:"user_id"`
	// TeamID optionally assigns the document to a team.
	TeamID *string `json:"team_id,omitzero"`
}

// Op is a single compacted, validated, and authorized operation passed to a
// [Handler].
type Op struct {
	// Meta identifies the document. For child types, UserID and TeamID hold
	// the identity resolved from the root document.
	Meta Meta
	// Action is the kind of mutation to apply.
	Action Action
	// Time is the HLC timestamp deciding last-write-wins.
	Time hlc.Time
	// Data is the full document payload; nil for deletes.
	Data jsontext.Value
}

// Window bounds a feed scan: rows with Since < seq < Until, capped at Limit.
type Window struct {
	// Since is the exclusive lower sequence bound.
	Since int64
	// Until is the exclusive upper sequence bound.
	Until int64
	// Limit caps the number of returned rows.
	Limit int
}

// Version is one row of feed output prior to patch assembly.
type Version struct {
	// ID is the document identifier.
	ID uuid.UUID
	// Seq is the storage sequence at which this version was recorded.
	Seq int64
	// Time is the HLC timestamp of this version, driving client-side
	// last-write-wins application.
	Time hlc.Time
	// Deleted marks tombstones.
	Deleted bool
	// Data is the full document payload; nil when Deleted.
	Data jsontext.Value
}

// Handler applies and reads changes for one document model. Implementations
// must enforce row-level last-write-wins, honor tombstones, and verify that
// existing rows targeted by an operation lie within the caller's scope (see
// the reference implementation in driver/postgres).
type Handler[Tx any] interface {
	// Upsert applies create-or-replace operations in bulk.
	Upsert(ctx context.Context, tx Tx, scope Scope, ops []Op) error
	// Delete removes documents and records tombstones in bulk.
	Delete(ctx context.Context, tx Tx, scope Scope, ops []Op) error
	// Fetch returns live versions and tombstones visible to the scope
	// within the window, in ascending sequence order.
	Fetch(ctx context.Context, tx Tx, scope Scope, w Window) ([]Version, error)
	// Resolve returns the identifying envelope of the given live documents,
	// keyed by ID; absent documents are omitted. For child types, UserID
	// and TeamID carry the denormalized root identity.
	Resolve(
		ctx context.Context,
		tx Tx,
		ids []uuid.UUID,
	) (map[uuid.UUID]Meta, error)
}

// Describer is an optional interface a [Handler] may implement to declare
// the structural expectations it was built with. When a registered handler
// implements it, [New] cross-checks those expectations against the
// registry and panics on any mismatch — catching, at startup, the class of
// bug where a handler and its registry entry are configured with different
// model names or parent references (which would otherwise silently break
// the patch feed). The reference driver/postgres.Table implements it.
type Describer interface {
	// Model reports the model name the handler was built for. It must equal
	// the name the handler is registered under.
	Model() string
	// Parent reports the ownership parent field the handler persists a
	// child's reference from, or ("", false) for a root handler. The field
	// must equal the one declared with [Owner].
	Parent() (via string, ok bool)
}

// Store provides the shared transactional machinery the engine builds on.
// Implementations must guarantee that sequence values are strictly monotonic
// and that Lock serializes all writers and readers sharing a key.
type Store[Tx any] interface {
	// Exec runs fn within a single transaction, committing on nil and
	// rolling back on error.
	Exec(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error
	// Lock acquires transaction-scoped advisory locks: shared for keys the
	// request only reads (feed visibility), exclusive for keys it writes.
	// Writers and readers of a key serialize; concurrent readers do not.
	// Implementations must acquire all keys in one global sort order,
	// regardless of mode, to stay deadlock-free.
	Lock(ctx context.Context, tx Tx, shared, exclusive []string) error
	// Floor returns the minimum valid cursor. Requests starting below it
	// must trigger a full resync.
	Floor(ctx context.Context, tx Tx) (int64, error)
	// Barrier consumes and returns the next sequence value, fencing the
	// caller's own writes off from the feed scan.
	Barrier(ctx context.Context, tx Tx) (int64, error)
	// Watermark returns the highest sequence value assigned so far.
	Watermark(ctx context.Context, tx Tx) (int64, error)
	// Claim records the given mutation IDs and returns the subset that was
	// not seen before.
	Claim(
		ctx context.Context,
		tx Tx,
		userID string,
		ids []uuid.UUID,
	) ([]uuid.UUID, error)
	// Grants returns, for each of the given owners, the identifiers of
	// the teams currently granted access to their personal documents. The
	// engine folds these into the lock set whenever a request writes
	// personal documents, keeping grant-based readers inside the lock
	// fence.
	Grants(
		ctx context.Context,
		tx Tx,
		owners []string,
	) (map[string][]string, error)
}

// Prefilter is an optional fast-path duplicate filter (e.g. backed by
// Valkey) consulted before the transaction. The transactional [Store.Claim]
// remains the source of truth; a prefilter only reduces wasted work.
type Prefilter interface {
	// Filter returns the subset of ids that are possibly new. False
	// positives are acceptable; false negatives are not.
	Filter(ctx context.Context, ids []uuid.UUID) ([]uuid.UUID, error)
	// Mark records ids as processed. It is called after a successful
	// commit and is best-effort.
	Mark(ctx context.Context, ids []uuid.UUID) error
}
