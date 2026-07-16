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
	"uuid"

	"github.com/deep-rent/nexus/valid"
)

// ErrTooManyChanges is returned when a request exceeds the configured
// maximum change set size.
var ErrTooManyChanges = errors.New("change set exceeds maximum size")

// ErrConflict is returned when the lock set could not be stabilized across
// the configured number of transaction attempts; the client should retry.
var ErrConflict = errors.New("concurrent ownership change, retry sync")

// TypeError reports changes referencing entity types that are not
// registered.
type TypeError struct {
	// IDs lists the offending mutation identifiers.
	IDs []uuid.UUID
	// Types lists the distinct unknown type names.
	Types []string
}

func (e *TypeError) Error() string {
	return "change set references unknown entity types"
}

// AuthzError reports changes whose payload identity lies outside the
// caller's scope.
type AuthzError struct {
	// IDs lists the offending mutation identifiers.
	IDs []uuid.UUID
}

func (e *AuthzError) Error() string {
	return "change set violates the authorized scope"
}

// DriftError reports changes carrying HLC timestamps too far in the future.
type DriftError struct {
	// IDs lists the offending mutation identifiers.
	IDs []uuid.UUID
}

func (e *DriftError) Error() string {
	return "change timestamps exceed the maximum clock drift"
}

// PayloadError reports document payloads that failed validation, keyed by
// mutation identifier.
type PayloadError struct {
	// Errors maps each offending mutation ID to its validation failures.
	Errors map[uuid.UUID]valid.Error
}

func (e *PayloadError) Error() string {
	return "change payloads failed validation"
}

// ResyncError reports that the requested cursor predates the retention
// floor; the client must perform a full resync from cursor zero.
type ResyncError struct {
	// Floor is the minimum valid cursor.
	Floor Cursor
}

func (e *ResyncError) Error() string {
	return "cursor predates the retention floor, full resync required"
}
