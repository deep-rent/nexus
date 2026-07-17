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
// is guaranteed by transactional mutation deduplication; and related models
// apply in dependency order on both server and client.
//
// Documents are isolated per user and team: every document belongs to a user
// (its immutable owner) and optionally to a team. Owners may share their
// personal documents with teams through the built-in "share" model.
//
// # Usage
//
// Register one handler per document model, declare the relationships
// between models, construct an engine around a store, and mount the
// endpoint on a router. Roots carry ownership metadata; children declare
// the parent they inherit ownership from, and additional foreign key
// dependencies order the patch feed for the client.
//
// Example:
//
//	store := postgres.New(db)
//	addresses := postgres.NewTable(store, "address", "addresses")
//	assets := postgres.NewTable(store, "asset", "assets")
//	contracts := postgres.NewTable(store, "contract", "contracts",
//		postgres.WithParent("assets", "asset_id"))
//
//	reg := diff.NewRegistry[*sql.Tx]()
//
//	// Roots carry id, user_id, and team_id in their payloads.
//	reg.Register[Address]("address", addresses, diff.Root())
//	reg.Register[Asset]("asset", assets, diff.Root(),
//		diff.Parents("address")) // assets reference an address (FK order)
//
//	// Children inherit ownership from their parent document, referenced
//	// by the "asset_id" field of the contract payload.
//	reg.Register[Contract]("contract", contracts,
//		diff.Owner("asset", "asset_id"))
//
//	// Enable personal-document sharing.
//	reg.RegisterShares(store.Shares())
//
//	engine := diff.New(store, reg)
//	diff.Mount[*auth.Claims](r, engine, guard.Secure())
//
// # Model
//
// The engine coordinates three independent clocks, and correctness rests on
// how they interlock. Understanding them is essential before changing the
// pipeline.
//
//   - The Hybrid Logical Clock (HLC) decides conflicts. Every document
//     version carries the HLC timestamp of the mutation that produced it;
//     an upsert wins only if its timestamp strictly exceeds the stored
//     row's (last-write-wins). The HLC is causal but says nothing about
//     delivery order.
//
//   - A single global sequence orders delivery. Every write assigns a fresh,
//     strictly increasing sequence value to its row (via nextval); the feed
//     is a scan over this sequence, and the client cursor is a sequence
//     position. The sequence — not the HLC — drives pagination, because it
//     is dense, monotonic, and free of the ties an HLC can produce.
//
//   - The retention floor bounds history. Tombstone pruning advances a
//     floor; a cursor below it can no longer be trusted to have seen every
//     deletion, so the client must resync from zero.
//
// One request runs this timeline inside a single transaction:
//
//	Floor(1) → Barrier → apply writes → Fetch(since, barrier) →
//
// Watermark → Floor(2)
//
//   - Floor(1) rejects a cursor that already predates the pruning floor.
//   - Barrier consumes one sequence value up front. Every row written by
//     this request gets a sequence above the barrier, so scanning strictly
//     below it fences the request's own writes out of its feed (a device
//     never echoes its own push). The barrier is also the feed's exclusive
//     upper bound.
//   - The writes apply, each taking sequence values above the barrier.
//   - Fetch returns rows and tombstones with since < seq < barrier, the
//     work the client missed, excluding this request's own writes.
//   - When the page is not full (More is false), the cursor advances to the
//     Watermark — the highest sequence assigned so far — which jumps the
//     client past its own just-written rows permanently. When the page is
//     full, the cursor is the last delivered row's sequence instead, so the
//     next page resumes exactly where this one stopped.
//   - Floor(2) re-reads the floor after the scan: tombstone pruning runs
//     outside the request's locks and could have advanced the floor past
//     the cursor mid-scan, which must convert into a resync.
//
// # Isolation
//
// The sequence guarantees ordering only if concurrent syncs of the same
// documents do not interleave their barrier/scan windows. The engine
// enforces this with per-scope advisory locks (see [Engine] internals and
// [Store.Lock]): a request takes a shared lock on the scope keys it only
// reads and an exclusive lock on every identity it writes, including the
// stored identity of any row it moves or deletes and the teams an owner has
// shared personal documents to. Two readers proceed concurrently; a writer
// and any reader of a shared key serialize. This is the invariant that
// makes the barrier fence sound, so every write path — including
// backend-initiated writes, which must go through [Store.Mutate] — must
// hold the same locks.
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
//   - Apply incoming rows with last-write-wins: an update wins against any
//     local state whose timestamp is less than OR EQUAL to the row's time —
//     a pending local edit with an equal timestamp lost the conflict on the
//     server and must be discarded, or replicas diverge. A deletion wins
//     against local state with a lower or equal timestamp, except when the
//     same page carries an update for the same document at an equal or
//     higher timestamp (the document moved audiences rather than dying).
//     Echoes of the device's own writes are harmless under these rules.
//   - When [Response.More] is true, immediately sync again from
//     [Response.Next] before processing user activity.
//   - On a "resync_required" error, clear the local cursor and sync from
//     zero; local pending mutations are preserved and re-pushed as usual.
//   - Deleting a share implies losing access: when a share tombstone
//     arrives, purge the granting owner's personal documents locally.
//   - A "changes_rejected" error is atomic: nothing from the request was
//     applied. Its context maps each rejected mutation ID to a [Cause];
//     handle each code as documented on the [Code] constants, repair or
//     drop the offending changes, and resend the remainder.
//   - On "conflict_retry", resend the identical request (dedup makes this
//     safe); on "too_many_changes", split the queue into smaller batches.
package diff
