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

package diff

import (
	"encoding/json/jsontext"
	"uuid"

	"github.com/deep-rent/nexus/internal/hlc"
	"github.com/deep-rent/nexus/valid"
)

// Stamp is a Hybrid Logical Clock timestamp as it travels over the wire.
// By construction it never exceeds 2^53 - 1, so it serializes as a plain
// JSON integer that survives IEEE 754 doubles and can be stored as a Long
// (or SQLite INTEGER) on the client.
type Stamp = hlc.Time

// Cursor is an opaque feed position. Clients persist the value returned in
// [Response.Next] and echo it back verbatim as [Request.Since] on their next
// sync. Zero means "from the beginning" and triggers a full resync.
type Cursor int64

// Action describes the kind of mutation a [Change] applies.
type Action string

const (
	// ActionUpsert creates or fully replaces a document.
	ActionUpsert Action = "upsert"
	// ActionDelete removes a document, leaving a tombstone behind.
	ActionDelete Action = "delete"
)

// Change is a single client-side mutation submitted for ingestion.
type Change struct {
	// ID is the client-assigned mutation identifier used for idempotent
	// deduplication. It must be a UUIDv7.
	ID uuid.UUID `json:"id"`
	// Action specifies whether the document is upserted or deleted.
	Action Action `json:"action"`
	// Model names the registered document model the change applies to.
	Model string `json:"type"`
	// Data carries the document payload. Upserts provide the full document;
	// deletes provide at least the identifying envelope.
	Data jsontext.Value `json:"data,omitzero"`
	// Time is the HLC timestamp of the mutation on the producing device.
	Time Stamp `json:"time"`
}

// Request is the unified sync payload: it pushes the client's pending
// changes and requests the patch feed accumulated since its last sync.
type Request struct {
	// Since is the cursor returned by the previous sync, or zero on first
	// contact.
	Since Cursor `json:"since"`
	// Limit caps the number of documents returned in the patch feed.
	// Zero applies the server default.
	Limit int `json:"limit,omitempty"`
	// Changes lists the client's pending mutations, oldest first.
	Changes []Change `json:"changes,omitempty"`
}

// Validate implements the [valid.Validatable] interface. Only the request
// envelope is validated here; per-change problems are reported through the
// unified [Error] with per-mutation causes instead.
func (r *Request) Validate(v *valid.Validator) {
	v.MinInt64("since", int64(r.Since), 0)
	v.MinInt("limit", r.Limit, 0)
}

var _ valid.Validatable = (*Request)(nil)

// Row is one document version delivered in a patch. Clients apply it with
// last-write-wins semantics: an incoming row wins against any local state
// whose timestamp is less than or equal to the row's time.
type Row struct {
	// Time is the HLC timestamp of this document version.
	Time Stamp `json:"time"`
	// Data is the full document payload.
	Data jsontext.Value `json:"data"`
}

// Deletion is one removed (or no longer visible) document delivered in a
// patch. Clients delete the document unless they hold a strictly newer
// version: at equal timestamps, an update in the same page wins over the
// deletion.
type Deletion struct {
	// ID is the identifier of the removed document.
	ID uuid.UUID `json:"id"`
	// Time is the HLC timestamp of the removal.
	Time Stamp `json:"time"`
}

// Patch groups the feed output for a single document model.
type Patch struct {
	// ID identifies this patch envelope. It carries no synchronization
	// semantics and exists purely as a tracing key for client pipelines.
	ID uuid.UUID `json:"id"`
	// Model names the document model all entries in this patch belong to.
	Model string `json:"type"`
	// Delete lists removed documents. Patches are emitted in an order safe
	// for client-side foreign keys: deletions arrive children-first.
	Delete []Deletion `json:"delete,omitempty"`
	// Update lists full document versions to be upserted, parents-first.
	Update []Row `json:"update,omitempty"`
}

// Response is the outcome of a sync round-trip.
type Response struct {
	// Patches contains the missed changes in order of application.
	Patches []Patch `json:"patches"`
	// Next is the cursor to persist and send as "since" on the next sync.
	Next Cursor `json:"next"`
	// More reports whether additional patches are pending beyond the
	// requested limit. If true, the client should sync again immediately,
	// starting from Next.
	More bool `json:"more"`
}
