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
	"errors"
	"fmt"

	"uuid"

	"github.com/deep-rent/nexus/valid"
)

// ErrTooManyChanges is returned when a request exceeds the configured
// maximum change set size. Clients should split their pending queue into
// smaller batches and sync each in turn.
var ErrTooManyChanges = errors.New("change set exceeds maximum size")

// ErrConflict is returned when a concurrent ownership change interfered
// with the sync. The condition is transient; clients should simply retry
// the identical request (idempotency makes this safe).
var ErrConflict = errors.New("concurrent ownership change, retry sync")

// Code classifies why an individual change was rejected. Every code implies
// a specific client reaction, documented on the respective constant.
type Code string

const (
	// CodeUnknownModel marks changes referencing a model the server does
	// not know. This indicates a schema mismatch between client and server;
	// the client should keep the change queued and prompt for an app
	// update, or drop it if the model was intentionally removed.
	CodeUnknownModel Code = "unknown_model"

	// CodeInvalid marks changes whose payload failed validation (malformed
	// envelope, missing fields, or model-specific rules; details in
	// [Cause.Fields]). Retrying unchanged will fail forever: the client
	// must repair the document locally or drop the change.
	CodeInvalid Code = "invalid"

	// CodeForbidden marks changes touching documents outside the caller's
	// scope. The client should drop the change, refresh its token (team
	// memberships may have changed), and perform a full resync if the
	// mismatch persists.
	CodeForbidden Code = "forbidden"

	// CodeDrift marks changes the server clock could not accept: a timestamp
	// too far in the future (usually a wrong device clock), or too many
	// mutations sharing one second (logical counter exhaustion). The client
	// should re-stamp its pending changes with fresh HLC timestamps after
	// correcting the clock, then retry.
	CodeDrift Code = "drift"

	// CodeOrphaned marks child changes referencing a parent document that
	// does not exist. The client should push the parent first (fix queue
	// ordering) or drop the change if the parent was deleted meanwhile.
	CodeOrphaned Code = "orphaned"
)

// Cause explains the rejection of a single change.
type Cause struct {
	// Code classifies the rejection.
	Code Code `json:"code"`
	// Fields details validation failures per document field. It is only
	// populated for [CodeInvalid].
	Fields valid.Error `json:"fields,omitzero"`
}

// Error reports rejected changes of a sync request, keyed by mutation ID.
// Requests are atomic: if any change is rejected, no change from the
// request is applied. Causes are collected per pipeline stage, so repairing
// one round of causes may surface further rejections on the next attempt.
type Error struct {
	// Causes maps each rejected mutation ID to the reason for rejection.
	Causes map[uuid.UUID]Cause
}

func (e *Error) Error() string {
	return fmt.Sprintf("%d changes rejected", len(e.Causes))
}

// Forbidden reports whether any change was rejected as [CodeForbidden],
// which upgrades the HTTP response from 400 to 403.
func (e *Error) Forbidden() bool {
	for _, cause := range e.Causes {
		if cause.Code == CodeForbidden {
			return true
		}
	}
	return false
}

// reject records a rejection cause, initializing the map on first use.
func (e *Error) reject(id uuid.UUID, cause Cause) {
	if e.Causes == nil {
		e.Causes = make(map[uuid.UUID]Cause)
	}
	e.Causes[id] = cause
}

// or returns nil (as error) when no change was rejected, and e otherwise.
// It avoids the classic non-nil interface around a nil pointer.
func (e *Error) or() error {
	if len(e.Causes) == 0 {
		return nil
	}
	return e
}

// ResyncError is returned when the requested cursor predates the retention
// floor. The client must clear its cursor and perform a full resync from
// zero; locally queued mutations are preserved and re-pushed as usual.
type ResyncError struct {
	// Floor is the minimum valid cursor.
	Floor Cursor
}

func (e *ResyncError) Error() string {
	return "cursor predates the retention floor, full resync required"
}
