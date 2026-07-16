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
	"context"
	"errors"
	"net/http"

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/router"
	"github.com/deep-rent/nexus/valid"
)

// Error reasons emitted by the sync endpoint, complementing the reasons
// defined by the router and auth packages. The per-change rejection codes
// accompanying ReasonChangesRejected are documented on the [Code]
// constants, including the appropriate client reaction for each.
const (
	// ReasonChangesRejected indicates that one or more changes were
	// rejected; the response context maps each rejected mutation ID to its
	// [Cause]. No change from the request was applied.
	ReasonChangesRejected = "changes_rejected"
	// ReasonDelegationRequired indicates a machine token where an end-user
	// context was required.
	ReasonDelegationRequired = "delegation_required"
	// ReasonConflict indicates a concurrent ownership change; the client
	// should retry the identical request.
	ReasonConflict = "conflict_retry"
	// ReasonResyncRequired indicates a cursor below the retention floor;
	// the client must restart from cursor zero.
	ReasonResyncRequired = "resync_required"
	// ReasonTooManyChanges indicates a change set above the configured
	// maximum size; the client should split its queue into smaller batches.
	ReasonTooManyChanges = "too_many_changes"
)

// Syncer is the engine capability the HTTP layer builds on. It is
// implemented by [Engine] and decouples the endpoint from the storage
// transaction type.
type Syncer interface {
	// Sync ingests a change set and compiles the missed patch feed.
	Sync(ctx context.Context, scope Scope, req *Request) (*Response, error)
}

// Endpoint builds the unified sync handler around the engine. Requests
// must carry claims verified and injected by an [auth.Guard] middleware
// generic over C, e.g.:
//
//	guard := auth.NewGuard[*auth.Claims](verifier)
//	r.HandleFunc("POST /sync", diff.Endpoint[*auth.Claims](engine),
//		guard.Secure())
//
// The subject claim identifies the syncing user and the "teams" claim
// (via [auth.AccessClaims.Memberships]) carries their team memberships.
func Endpoint[C auth.AccessClaims](s Syncer) router.HandlerFunc {
	if s == nil {
		panic("syncer is required")
	}
	return func(e *router.Exchange) error {
		claims, ok := auth.From[C](e)
		if !ok {
			return &router.Error{
				Status:      http.StatusUnauthorized,
				Reason:      auth.ReasonMissingToken,
				Description: "The sync endpoint requires authentication.",
			}
		}
		if !claims.Delegated() {
			return &router.Error{
				Status: http.StatusForbidden,
				Reason: ReasonDelegationRequired,
				Description: "The sync endpoint serves end users; " +
					"machine tokens cannot sync documents.",
			}
		}
		sub := claims.Subject()
		if !valid.UUID(sub) {
			return &router.Error{
				Status:      http.StatusUnauthorized,
				Reason:      auth.ReasonInvalidToken,
				Description: "The token subject is not a user identifier.",
			}
		}

		// Team memberships flow into ::uuid casts throughout the store, so
		// a single malformed value would fail the whole transaction as a
		// raw 500. Reject the token cleanly instead, symmetric with the
		// subject check above.
		teams := claims.Memberships()
		for _, team := range teams {
			if !valid.UUID(team) {
				return &router.Error{
					Status:      http.StatusUnauthorized,
					Reason:      auth.ReasonInvalidToken,
					Description: "A team membership is not a valid identifier.",
				}
			}
		}

		var req Request
		if aerr := e.BindJSON(&req); aerr != nil {
			return aerr
		}

		scope := Scope{UserID: sub, Teams: teams}
		resp, err := s.Sync(e.Context(), scope, &req)
		if err != nil {
			return translate(err)
		}
		return e.JSON(http.StatusOK, resp)
	}
}

// Mount registers the sync endpoint as "POST /sync" following the mount
// convention of this framework. Pass the auth guard (and any additional
// route middleware) as mws. For a custom pattern, register [Endpoint] with
// [router.Router.HandleFunc] directly.
func Mount[C auth.AccessClaims](
	r *router.Router,
	s Syncer,
	mws ...router.Middleware,
) {
	r.HandleFunc("POST /sync", Endpoint[C](s), mws...)
}

// translate maps the engine's typed errors onto HTTP error responses.
func translate(err error) error {
	if rejected, ok := errors.AsType[*Error](err); ok {
		status := http.StatusBadRequest
		if rejected.Forbidden() {
			status = http.StatusForbidden
		}
		return &router.Error{
			Status: status,
			Reason: ReasonChangesRejected,
			Description: "Some changes were rejected; " +
				"no change from this request was applied.",
			Context: rejected.Causes,
			Cause:   err,
		}
	}
	if rerr, ok := errors.AsType[*ResyncError](err); ok {
		return &router.Error{
			Status:      http.StatusGone,
			Reason:      ReasonResyncRequired,
			Description: "The cursor is too old; restart from cursor zero.",
			Context:     map[string]any{"floor": rerr.Floor},
			Cause:       err,
		}
	}
	if errors.Is(err, ErrConflict) {
		return &router.Error{
			Status:      http.StatusConflict,
			Reason:      ReasonConflict,
			Description: "A concurrent change interfered; retry the sync.",
			Cause:       err,
		}
	}
	if errors.Is(err, ErrTooManyChanges) {
		return &router.Error{
			Status:      http.StatusRequestEntityTooLarge,
			Reason:      ReasonTooManyChanges,
			Description: "The change set exceeds the maximum size.",
			Cause:       err,
		}
	}
	return err
}
