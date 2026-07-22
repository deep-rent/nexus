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
	"net/http"
	"testing"

	"uuid"

	"github.com/deep-rent/nexus/net/router"
)

func TestError_Message(t *testing.T) {
	t.Parallel()

	e := &Error{}
	e.reject(uuid.NewV7(), Cause{Code: CodeInvalid})
	e.reject(uuid.NewV7(), Cause{Code: CodeForbidden})
	if got := e.Error(); got != "2 changes rejected" {
		t.Errorf("got %q; want %q", got, "2 changes rejected")
	}

	r := &ResyncError{Floor: 42}
	if r.Error() == "" {
		t.Error("resync error message should not be empty")
	}
}

func TestTranslate(t *testing.T) {
	t.Parallel()

	forbidden := &Error{}
	forbidden.reject(uuid.NewV7(), Cause{Code: CodeForbidden})

	invalid := &Error{}
	invalid.reject(uuid.NewV7(), Cause{Code: CodeInvalid})

	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantReason string
	}{
		{
			name:       "rejected forbidden upgrades to 403",
			err:        forbidden,
			wantStatus: http.StatusForbidden,
			wantReason: ReasonChangesRejected,
		},
		{
			name:       "rejected invalid stays 400",
			err:        invalid,
			wantStatus: http.StatusBadRequest,
			wantReason: ReasonChangesRejected,
		},
		{
			name:       "resync",
			err:        &ResyncError{Floor: 7},
			wantStatus: http.StatusGone,
			wantReason: ReasonResyncRequired,
		},
		{
			name:       "conflict",
			err:        ErrConflict,
			wantStatus: http.StatusConflict,
			wantReason: ReasonConflict,
		},
		{
			name:       "too many changes",
			err:        ErrTooManyChanges,
			wantStatus: http.StatusRequestEntityTooLarge,
			wantReason: ReasonTooManyChanges,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := translate(tt.err)
			re, ok := errors.AsType[*router.Error](got)
			if !ok {
				t.Fatalf("got %T; want *router.Error", got)
			}
			if re.Status != tt.wantStatus {
				t.Errorf("status: got %d; want %d", re.Status, tt.wantStatus)
			}
			if re.Reason != tt.wantReason {
				t.Errorf("reason: got %q; want %q", re.Reason, tt.wantReason)
			}
		})
	}

	// An unrecognized error passes through unchanged.
	other := errors.New("operational")
	if got := translate(other); got != other {
		t.Errorf("got %v; want the original error unchanged", got)
	}
}
