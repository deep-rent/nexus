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
	"strconv"

	"uuid"

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/header"
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
	// ReasonConflict indicates a concurrent ownership change; the client
	// should retry the identical request.
	ReasonConflict = "conflict_retry"
	// ReasonResyncRequired indicates a cursor below the retention floor;
	// the client must restart from cursor zero.
	ReasonResyncRequired = "resync_required"
	// ReasonTooManyChanges indicates a change set above the configured
	// maximum size; the client should split its queue into smaller batches.
	ReasonTooManyChanges = "too_many_changes"
	// ReasonUnknownModel indicates that the requested document type is not
	// served by this endpoint.
	ReasonUnknownModel = "unknown_model"
)

// Syncer is the engine capability the HTTP layer builds on. It is
// implemented by [Engine] and decouples the endpoint from the storage
// transaction type.
type Syncer interface {
	// Sync ingests a change set and compiles the missed patch feed.
	Sync(ctx context.Context, scope Scope, req *Request) (*Response, error)
}

// Getter is the engine capability behind the single-document endpoint. It
// is implemented by [Engine] and decouples the endpoint from the storage
// transaction type.
type Getter interface {
	// Get returns the live version of a single document by model name and
	// ID, subject to the scope's visibility.
	Get(ctx context.Context, scope Scope, model string, id uuid.UUID) (
		*Document, error)
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
		scope, aerr := scopeFrom[C](e)
		if aerr != nil {
			return aerr
		}

		var req Request
		if aerr := e.BindJSON(&req); aerr != nil {
			return aerr
		}

		resp, err := s.Sync(e.Context(), scope, &req)
		if err != nil {
			return translate(err)
		}
		return e.JSON(http.StatusOK, resp)
	}
}

// DocumentEndpoint builds the single-document retrieval handler around the
// engine. It serves "GET /{type}/{id}" requests, returning the live version
// of one document subject to the caller's visibility, and shares the
// authentication requirements of [Endpoint]:
//
//	guard := auth.NewGuard[*auth.Claims](verifier)
//	get := diff.DocumentEndpoint[*auth.Claims](engine)
//	r.HandleFunc("GET /{type}/{id}", get, guard.Secure())
//
// The {type} parameter names a registered document model and {id} the
// document identifier. Absent, deleted, and out-of-scope documents
// uniformly yield 404 so callers cannot probe foreign document IDs.
//
// Responses carry a strong ETag derived from the document's HLC timestamp,
// and requests may revalidate with If-None-Match: an unchanged document
// answers 304 Not Modified without a body, so integrators can poll cheaply.
func DocumentEndpoint[C auth.AccessClaims](g Getter) router.HandlerFunc {
	if g == nil {
		panic("getter is required")
	}
	return func(e *router.Exchange) error {
		scope, aerr := scopeFrom[C](e)
		if aerr != nil {
			return aerr
		}

		id, err := uuid.Parse(e.Param("id"))
		if err != nil {
			return &router.Error{
				Status:      http.StatusBadRequest,
				Reason:      router.ReasonValidationFailed,
				Description: "document ID is not a valid UUID",
				Context: valid.Error{
					"id": {"must be a valid UUID"},
				},
			}
		}

		doc, err := g.Get(e.Context(), scope, e.Param("type"), id)
		if err != nil {
			return translate(err)
		}

		// The HLC timestamp uniquely versions a document, so it doubles as
		// a strong entity tag: every applied write carries a strictly
		// greater stamp than the version it replaced (including
		// resurrections, which must beat the tombstone), and visibility-only
		// re-sequencing (team-move cascades, grant touches) never alters the
		// payload. Caching is private (visibility is per-user) and no-cache
		// (revalidate on every use), which is exactly the ETag polling loop.
		etag := header.Quote(strconv.FormatInt(int64(doc.Time), 10))
		e.SetHeader("ETag", etag)
		e.SetHeader("Cache-Control", "private, no-cache")
		if header.MatchETag(e.GetHeader("If-None-Match"), etag) {
			e.Status(http.StatusNotModified)
			return nil
		}
		return e.JSON(http.StatusOK, doc)
	}
}

// scopeFrom extracts the authorization scope from the request's verified
// claims: the subject identifies the acting user and the "teams" claim (via
// [auth.AccessClaims.Memberships]) carries their team memberships. It
// rejects unauthenticated requests and machine tokens.
func scopeFrom[C auth.AccessClaims](e *router.Exchange) (Scope, *router.Error) {
	claims, ok := auth.From[C](e)
	if !ok {
		return Scope{}, &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonMissingToken,
			Description: "this endpoint requires authentication",
		}
	}
	if !claims.Delegated() {
		return Scope{}, &router.Error{
			Status: http.StatusForbidden,
			Reason: auth.ReasonDelegationRequired,
			Description: "this endpoint serves end users; " +
				"machine tokens cannot access documents",
		}
	}
	// The raw sub claim is an opaque string; UserID performs the UUID
	// parse and returns the zero value for anything that is not a
	// well-formed, delegated user identifier.
	sub := claims.UserID()
	if sub == uuid.Nil() {
		return Scope{}, &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonInvalidToken,
			Description: "token subject is not a user identifier",
		}
	}
	return Scope{UserID: sub, Teams: claims.Memberships()}, nil
}

// Mount registers the sync endpoint as "POST /sync" following the mount
// convention of this framework. When s also implements [Getter] (as
// [Engine] does), the single-document endpoint is registered as
// "GET /{type}/{id}" alongside it. Pass the auth guard (and any additional
// route middleware) as mws. For custom patterns, register [Endpoint] and
// [DocumentEndpoint] with [router.Router.HandleFunc] directly.
//
// Note that "GET /{type}/{id}" is a root-level wildcard: it matches EVERY
// two-segment GET on the router. [http.ServeMux] gives more specific
// patterns precedence, so explicit sibling routes (say, "GET /teams/{id}")
// keep winning no matter the registration order — but any two-segment GET
// no other route claims reaches the document handler and answers 404 with
// reason "unknown_model" instead of the mux's plain 404. Mount the router
// under a path prefix (or register [DocumentEndpoint] on a custom pattern)
// if that catch-all behavior is undesirable.
func Mount[C auth.AccessClaims](
	r *router.Router,
	s Syncer,
	mws ...router.Middleware,
) {
	r.HandleFunc("POST /sync", Endpoint[C](s), mws...)
	if g, ok := s.(Getter); ok {
		r.HandleFunc("GET /{type}/{id}", DocumentEndpoint[C](g), mws...)
	}
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
			Description: "some changes were rejected; " +
				"no change from this request was applied",
			Context: rejected.Causes,
			Cause:   err,
		}
	}
	if rerr, ok := errors.AsType[*ResyncError](err); ok {
		return &router.Error{
			Status:      http.StatusGone,
			Reason:      ReasonResyncRequired,
			Description: "cursor is too old; restart from cursor zero",
			Context:     map[string]any{"floor": rerr.Floor},
			Cause:       err,
		}
	}
	if errors.Is(err, ErrConflict) {
		return &router.Error{
			Status:      http.StatusConflict,
			Reason:      ReasonConflict,
			Description: "a concurrent change interfered; retry the sync",
			Cause:       err,
		}
	}
	if errors.Is(err, ErrTooManyChanges) {
		return &router.Error{
			Status:      http.StatusRequestEntityTooLarge,
			Reason:      ReasonTooManyChanges,
			Description: "change set exceeds the maximum size",
			Cause:       err,
		}
	}
	// Unsupported models deliberately read as unknown: from the API
	// consumer's perspective, a type without point reads is simply not
	// served by this endpoint.
	if errors.Is(err, ErrUnknownModel) || errors.Is(err, ErrUnsupportedModel) {
		return &router.Error{
			Status:      http.StatusNotFound,
			Reason:      ReasonUnknownModel,
			Description: "the requested document type has not been recognized",
			Cause:       err,
		}
	}
	if errors.Is(err, ErrNotFound) {
		return &router.Error{
			Status:      http.StatusNotFound,
			Reason:      router.ReasonNotFound,
			Description: "the requested document does not exist",
			Cause:       err,
		}
	}
	return err
}
