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

// Package diff provides a bidirectional, offline-first synchronization engine
// for replicating documents between a backend store and mobile, web, or
// desktop clients.
//
// A single HTTP endpoint accepts a client's pending changes (push) and
// returns the patches it missed (pull) within one database transaction.
// Conflicts resolve deterministically via row-level last-write-wins over
// Hybrid Logical Clock timestamps; deletions leave tombstones; idempotency
// is guaranteed by transactional mutation deduplication; and related entity
// types apply in dependency order on both server and client.
//
// Documents are isolated per user and team: every document belongs to a user
// (its immutable owner) and optionally to a team. Owners may share their
// personal documents with teams through the built-in "share" entity type.
//
// # Usage
//
// Register one handler per entity type, construct an engine around a store,
// and mount the endpoint on a router.
//
// Example:
//
//	store := postgres.New(db)
//	assets := postgres.NewTable(store, "asset", "assets")
//
//	reg := diff.NewRegistry[*sql.Tx]()
//	reg.Register[Asset]("asset", assets, diff.WithRootMeta())
//
//	engine := diff.New(store, reg)
//	diff.Mount[*diff.Claims](r, engine, guard.Secure())
//
// # Client Contract
//
// Clients must follow these rules to preserve the engine's guarantees:
//
//   - Timestamps and cursors are plain JSON integers that never exceed
//     2^53 - 1; store them as 64-bit integers (e.g. a Kotlin Long or an
//     SQLite INTEGER). The cursor is opaque: persist [Response.Next]
//     verbatim and echo it as [Request.Since] on the next sync. Never
//     derive, compare, or arithmetically adjust cursors.
//   - Stamp every local mutation with a Hybrid Logical Clock timestamp
//     (33-bit Unix seconds shifted left by 20 bits, plus a 20-bit logical
//     counter), and merge every received timestamp into the local clock.
//   - Assign a fresh UUIDv7 to each mutation and keep it stable across
//     retries; the server deduplicates by mutation ID, so resending a
//     change set after a network failure is always safe.
//   - Apply each response page in one local transaction: patches carry
//     updates in parents-first order and must be applied in patch order;
//     deletions must be applied in reverse patch order (children first).
//   - When [Response.More] is true, immediately sync again from
//     [Response.Next] before processing user activity.
//   - A push may echo back documents the device itself just wrote when it
//     coincides with a paged backlog or a retried request. Echoes are
//     harmless; devices may drop incoming documents whose (id, time) pair
//     matches a change they pushed.
//   - On a "resync_required" error, clear the local cursor and sync from
//     zero; local pending mutations are preserved and re-pushed as usual.
//   - Deleting a share implies losing access: when a share tombstone
//     arrives, purge the granting owner's personal documents locally.
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
	// Deleted marks tombstones.
	Deleted bool
	// Data is the full document payload; nil when Deleted.
	Data jsontext.Value
}

// Handler applies and reads changes for one entity type. Implementations
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

// Store provides the shared transactional machinery the engine builds on.
// Implementations must guarantee that sequence values are strictly monotonic
// and that Lock serializes all writers and readers sharing a key.
type Store[Tx any] interface {
	// Exec runs fn within a single transaction, committing on nil and
	// rolling back on error.
	Exec(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error
	// Lock acquires exclusive, transaction-scoped locks on the given keys.
	// Implementations must sort the keys internally so concurrent callers
	// acquire them in the same order.
	Lock(ctx context.Context, tx Tx, keys []string) error
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
	// Touch re-sequences all personal documents (and their descendants) of
	// the given owner so they re-enter the patch feed. It is invoked after
	// the owner grants a team access to their personal documents.
	Touch(ctx context.Context, tx Tx, ownerID string) error
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
