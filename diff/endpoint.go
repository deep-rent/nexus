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

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/router"
	"github.com/deep-rent/nexus/valid"
)

// Error reasons emitted by the sync endpoint, complementing the reasons
// defined by the router and auth packages.
const (
	// ReasonUnknownType indicates changes referencing unregistered entity
	// types.
	ReasonUnknownType = "unknown_type"
	// ReasonBadPayload indicates document payloads that failed validation.
	ReasonBadPayload = "invalid_payload"
	// ReasonClockDrift indicates change timestamps too far in the future.
	ReasonClockDrift = "clock_drift"
	// ReasonScopeViolation indicates changes touching documents outside the
	// authenticated scope.
	ReasonScopeViolation = "scope_violation"
	// ReasonDelegationRequired indicates a machine token where an end-user
	// context was required.
	ReasonDelegationRequired = "delegation_required"
	// ReasonConflict indicates a concurrent ownership change; the client
	// should retry the sync.
	ReasonConflict = "conflict_retry"
	// ReasonResyncRequired indicates a cursor below the retention floor;
	// the client must restart from cursor zero.
	ReasonResyncRequired = "resync_required"
	// ReasonTooManyChanges indicates a change set above the configured
	// maximum size.
	ReasonTooManyChanges = "too_many_changes"
)

// TeamClaims is the minimal claim surface the sync endpoint requires: a
// verified JWT identity carrying team memberships and an authorized-party
// distinction.
type TeamClaims interface {
	jwt.Claims
	// TeamIDs returns the identifiers of all teams the subject belongs to.
	TeamIDs() []string
	// Delegated reports whether the token was issued to a client acting on
	// behalf of an end user rather than to the client itself.
	Delegated() bool
}

// Claims is a ready-made [TeamClaims] implementation carrying team
// memberships in a custom "teams" JWT claim.
type Claims struct {
	auth.Claims
	// Teams lists the identifiers of the subject's teams.
	Teams []string `json:"teams,omitempty"`
}

// TeamIDs implements the [TeamClaims] interface.
func (c *Claims) TeamIDs() []string {
	return c.Teams
}

var _ TeamClaims = (*Claims)(nil)

// Endpoint builds the unified sync handler around the engine. Requests
// must carry claims verified and injected by an [auth.Guard] middleware
// generic over C, e.g.:
//
//	guard := auth.NewGuard[*diff.Claims](verifier)
//	r.HandleFunc("POST /sync", diff.Endpoint[*diff.Claims](engine),
//		guard.Secure())
func Endpoint[C TeamClaims, Tx any](eng *Engine[Tx]) router.HandlerFunc {
	if eng == nil {
		panic("engine is required")
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

		var req Request
		if aerr := e.BindJSON(&req); aerr != nil {
			return aerr
		}

		scope := Scope{UserID: sub, Teams: claims.TeamIDs()}
		resp, err := eng.Sync(e.Context(), scope, &req)
		if err != nil {
			return translate(err)
		}
		return e.JSON(http.StatusOK, resp)
	}
}

// Mount registers the sync endpoint as "POST /sync" following the mount
// convention of this framework. Pass the auth guard (and any additional
// route middleware) as mws. For a custom pattern, register
// [Endpoint] with [router.Router.HandleFunc] directly.
func Mount[C TeamClaims, Tx any](
	r *router.Router,
	eng *Engine[Tx],
	mws ...router.Middleware,
) {
	r.HandleFunc("POST /sync", Endpoint[C](eng), mws...)
}

// translate maps the engine's typed errors onto HTTP error responses.
func translate(err error) error {
	if terr, ok := errors.AsType[*TypeError](err); ok {
		return &router.Error{
			Status:      http.StatusBadRequest,
			Reason:      ReasonUnknownType,
			Description: "The change set references unknown entity types.",
			Context: map[string]any{
				"ids":   terr.IDs,
				"types": terr.Types,
			},
			Cause: err,
		}
	}
	if perr, ok := errors.AsType[*PayloadError](err); ok {
		return &router.Error{
			Status:      http.StatusBadRequest,
			Reason:      ReasonBadPayload,
			Description: "Some document payloads failed validation.",
			Context:     perr.Errors,
			Cause:       err,
		}
	}
	if derr, ok := errors.AsType[*DriftError](err); ok {
		return &router.Error{
			Status:      http.StatusBadRequest,
			Reason:      ReasonClockDrift,
			Description: "Some change timestamps are too far in the future.",
			Context:     map[string]any{"ids": derr.IDs},
			Cause:       err,
		}
	}
	if aerr, ok := errors.AsType[*AuthzError](err); ok {
		return &router.Error{
			Status:      http.StatusForbidden,
			Reason:      ReasonScopeViolation,
			Description: "Some changes touch documents outside your scope.",
			Context:     map[string]any{"ids": aerr.IDs},
			Cause:       err,
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
