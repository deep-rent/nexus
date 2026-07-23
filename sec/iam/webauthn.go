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

package iam

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"net/http"

	"uuid"

	"github.com/deep-rent/nexus/dat/valid"
	"github.com/deep-rent/nexus/net/router"
	"github.com/deep-rent/nexus/sec/auth"
	"github.com/deep-rent/nexus/sec/iam/flow"
	"github.com/deep-rent/nexus/sec/iam/oauth"
	"github.com/deep-rent/nexus/sec/iam/passkey"
	"github.com/deep-rent/nexus/sys/log"
)

// WebAuthnOptionsResponse is the payload returned by the endpoints that
// begin a WebAuthn ceremony.
//
// The options are handed to the client-side WebAuthn API
// (navigator.credentials.create or .get); the handle references the pending
// ceremony and must be echoed back when the ceremony is finished.
type WebAuthnOptionsResponse struct {
	// Handle is the opaque reference to the pending ceremony.
	Handle string `json:"handle"`
	// ExpiresIn is the lifetime of the ceremony session in seconds.
	ExpiresIn int64 `json:"expires_in"`
	// Options carries the credential creation options (registration) or
	// credential request options (login) for the client-side WebAuthn API.
	Options any `json:"options"`
}

// WebAuthnRegistrationRequest represents the payload finishing a passkey
// registration ceremony.
//
// It is consumed by [Server.WebAuthnRegister].
type WebAuthnRegistrationRequest struct {
	// Handle is the ceremony reference returned by the options endpoint.
	Handle string `json:"handle"`
	// Name is an optional human-readable label for the new passkey (e.g.,
	// "MacBook Touch ID").
	Name string `json:"name,omitzero"`
	// Credential is the JSON-encoded PublicKeyCredential produced by
	// navigator.credentials.create (or the platform equivalent).
	Credential jsontext.Value `json:"credential"`
}

// Validate implements the [valid.Validatable] interface.
func (r *WebAuthnRegistrationRequest) Validate(v *valid.Validator) {
	v.NotEmpty("handle", r.Handle)
	if len(r.Credential) == 0 {
		v.Fail("credential", "must not be empty")
	}
}

var _ valid.Validatable = (*WebAuthnRegistrationRequest)(nil)

// WebAuthnLoginRequest represents the payload finishing a passkey login
// ceremony.
//
// It is consumed by [Server.WebAuthnLogin].
type WebAuthnLoginRequest struct {
	// Handle is the ceremony reference returned by the options endpoint.
	Handle string `json:"handle"`
	// Credential is the JSON-encoded PublicKeyCredential produced by
	// navigator.credentials.get (or the platform equivalent).
	Credential jsontext.Value `json:"credential"`
}

// Validate implements the [valid.Validatable] interface.
func (r *WebAuthnLoginRequest) Validate(v *valid.Validator) {
	v.NotEmpty("handle", r.Handle)
	if len(r.Credential) == 0 {
		v.Fail("credential", "must not be empty")
	}
}

var _ valid.Validatable = (*WebAuthnLoginRequest)(nil)

// account describes the subject to the passkey engine. The subject's UUID
// bytes double as the WebAuthn user handle, which discoverable credentials
// store on the authenticator and return with every assertion; this is what
// lets the login endpoints resolve the account without a username prompt.
func account(sub Subject, creds []passkey.Credential) passkey.Account {
	id := sub.ID()
	return passkey.Account{
		Handle:      id[:],
		Owner:       id.String(),
		Username:    sub.Username(),
		Credentials: creds,
	}
}

// subjectDirectory adapts the [SubjectStore] and [Stores.Credentials] to the
// [passkey.Directory] interface, resolving accounts from WebAuthn user
// handles during login ceremonies.
type subjectDirectory struct {
	s *Server
}

var _ passkey.Directory = subjectDirectory{}

// Lookup implements [passkey.Directory].
func (d subjectDirectory) Lookup(
	ctx context.Context,
	userHandle []byte,
) (passkey.Account, bool, error) {
	// User handles minted by this server are raw subject UUIDs; anything
	// else cannot belong to a known account.
	if len(userHandle) != len(uuid.UUID{}) {
		return passkey.Account{}, false, nil
	}
	id := uuid.UUID(userHandle)

	sub, err := d.s.subjects.GetSubject(ctx, id)
	if err != nil {
		return passkey.Account{}, false, err
	}
	if sub == nil {
		return passkey.Account{}, false, nil
	}

	creds, err := d.s.stores.Credentials.List(ctx, id.String())
	if err != nil {
		return passkey.Account{}, false, err
	}
	return account(sub, creds), true, nil
}

// webAuthnSubject resolves the subject on behalf of whom a registration
// ceremony runs. It accepts the session cookie established by the login
// endpoints (first-party web apps) or, as a fallback, a Bearer access token
// issued by this server (native apps that authenticated via a token grant
// and have no cookie jar).
//
// It returns nil (with a nil error) if neither credential identifies a
// subject, and an error only if a storage lookup fails.
func (s *Server) webAuthnSubject(e *router.Exchange) (Subject, error) {
	sub, err := s.subjectFromSession(e)
	if err != nil || sub != nil {
		return sub, err
	}

	token := auth.BearerExtractor(e.R)
	if token == "" {
		return nil, nil
	}

	claims, err := s.introspector.Verify([]byte(token))
	if err != nil {
		s.logger.Debug(
			e.Context(),
			"Token verification failed during WebAuthn registration",
			log.Err(err),
		)
		return nil, nil
	}

	// Only delegated tokens name a resource owner; a client-credentials
	// token cannot enroll passkeys.
	id := claims.UserID()
	if id == uuid.Nil() {
		return nil, nil
	}

	return s.subjects.GetSubject(e.Context(), id)
}

// WebAuthnRegisterOptions begins a passkey registration ceremony for an
// authenticated subject.
//
// The subject is identified via the session cookie or a Bearer access
// token; see [Server.WebAuthnRegister] for the accompanying finish step.
// The returned options exclude already registered credentials, require a
// discoverable credential, and demand user verification.
func (s *Server) WebAuthnRegisterOptions(e *router.Exchange) error {
	if s.passkeys == nil {
		e.Status(http.StatusNotFound)
		return nil
	}

	sub, err := s.webAuthnSubject(e)
	if err != nil {
		return router.ServerError("failed to lookup subject", err)
	}
	if sub == nil {
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "login required",
		}
	}

	creds, err := s.stores.Credentials.List(e.Context(), sub.ID().String())
	if err != nil {
		return router.ServerError("failed to retrieve credentials", err)
	}

	handle, options, expiresIn, err := s.passkeys.BeginRegistration(
		e.Context(),
		account(sub, creds),
	)
	if err != nil {
		return router.ServerError("failed to begin registration", err)
	}

	return e.JSON(http.StatusOK, WebAuthnOptionsResponse{
		Handle:    handle,
		ExpiresIn: expiresIn,
		Options:   options,
	})
}

// WebAuthnRegister finishes a passkey registration ceremony by verifying
// the authenticator's attestation response and persisting the new
// credential via [Stores.Credentials].
//
// It expects a [WebAuthnRegistrationRequest] carrying the handle returned
// by [Server.WebAuthnRegisterOptions] and must be called by the same
// subject that began the ceremony. Ceremony sessions are single use: any
// finish attempt, successful or not, burns the handle.
func (s *Server) WebAuthnRegister(e *router.Exchange) error {
	if s.passkeys == nil {
		e.Status(http.StatusNotFound)
		return nil
	}

	sub, err := s.webAuthnSubject(e)
	if err != nil {
		return router.ServerError("failed to lookup subject", err)
	}
	if sub == nil {
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "login required",
		}
	}

	var req WebAuthnRegistrationRequest
	if err := e.BindJSON(&req); err != nil {
		return err
	}

	out, err := s.passkeys.FinishRegistration(
		e.Context(),
		account(sub, nil),
		req.Name,
		req.Handle,
		req.Credential,
	)
	if err != nil {
		return router.ServerError("failed to finish registration", err)
	}

	switch out.Status {
	case passkey.StatusInvalid:
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "invalid or expired handle",
		}
	case passkey.StatusRejected:
		s.logger.Debug(
			e.Context(),
			"WebAuthn attestation rejected",
			log.Err(out.Reason),
		)
		return &router.Error{
			Status:      http.StatusBadRequest,
			Reason:      router.ReasonValidationFailed,
			Description: "credential verification failed",
		}
	}

	e.NoContent()

	return nil
}

// WebAuthnLoginOptions begins a passkey login ceremony.
//
// The endpoint is anonymous: the returned options carry no credential
// allowlist, and the account is discovered from the user handle embedded in
// the assertion. The ceremony can be finished either via
// [Server.WebAuthnLogin] (first-party web login ending in a session
// cookie) or via the [oauth.GrantTypeWebAuthn] token grant (native apps
// exchanging the assertion directly for tokens).
func (s *Server) WebAuthnLoginOptions(e *router.Exchange) error {
	if s.passkeys == nil {
		e.Status(http.StatusNotFound)
		return nil
	}

	handle, options, expiresIn, err := s.passkeys.BeginLogin(e.Context())
	if err != nil {
		return router.ServerError("failed to begin login", err)
	}

	return e.JSON(http.StatusOK, WebAuthnOptionsResponse{
		Handle:    handle,
		ExpiresIn: expiresIn,
		Options:   options,
	})
}

// WebAuthnLogin finishes a passkey login ceremony and establishes a
// session.
//
// It expects a [WebAuthnLoginRequest] carrying the handle returned by
// [Server.WebAuthnLoginOptions] and the authenticator's assertion. On
// success, the same session cookie as after a password login is set; the
// standard authorization code flow can proceed from there. A passkey
// assertion with user verification is inherently multi-factor, so no OTP
// confirmation follows.
func (s *Server) WebAuthnLogin(e *router.Exchange) error {
	if s.passkeys == nil {
		e.Status(http.StatusNotFound)
		return nil
	}

	var req WebAuthnLoginRequest
	if err := e.BindJSON(&req); err != nil {
		return err
	}

	out, err := s.passkeys.FinishLogin(e.Context(), req.Handle, req.Credential)
	if err != nil {
		return router.ServerError("failed to finish login", err)
	}

	switch out.Status {
	case passkey.StatusInvalid:
		s.penalize(s.addr(e))
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "invalid or expired handle",
		}
	case passkey.StatusRejected:
		s.penalize(s.addr(e))
		s.logger.Debug(
			e.Context(),
			"WebAuthn assertion rejected",
			log.Err(out.Reason),
		)
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "assertion verification failed",
		}
	}

	sub, err := s.subjectOf(e.Context(), out.Owner)
	if err != nil {
		return router.ServerError("failed to lookup subject", err)
	}
	if sub == nil {
		return invalidLogin()
	}

	if err := s.session(e, sub, false); err != nil {
		return err
	}

	e.NoContent()

	return nil
}

// subjectOf resolves the subject behind an engine-reported owner reference.
// It returns nil (with a nil error) when the owner is malformed or no longer
// exists.
func (s *Server) subjectOf(ctx context.Context, owner string) (Subject, error) {
	id, err := uuid.Parse(owner)
	if err != nil {
		return nil, nil
	}
	return s.subjects.GetSubject(ctx, id)
}

// webAuthnGrant implements the custom [oauth.GrantTypeWebAuthn] grant. It
// lets a client exchange a passkey assertion directly for tokens, bypassing
// the browser-bound authorization code flow. The client obtains ceremony
// options from [Server.WebAuthnLoginOptions], performs the platform passkey
// ceremony, and submits the resulting assertion to the token endpoint:
//
//	grant_type=urn:ietf:params:oauth:grant-type:webauthn
//	handle=...    (ceremony reference from the options endpoint)
//	assertion=... (JSON-encoded PublicKeyCredential)
//	scope=...     (optional)
//
// The grant is registered automatically by [WithPasskeys]; clients must
// additionally be allowed to use it via [oauth.Client.CanUseGrant].
type webAuthnGrant struct {
	s *Server
}

var _ oauth.Grant = (*webAuthnGrant)(nil)

// Type implements the [oauth.Grant] interface.
func (g *webAuthnGrant) Type() oauth.GrantType { return oauth.GrantTypeWebAuthn }

// Authorize implements the [oauth.Grant] interface.
func (g *webAuthnGrant) Authorize(
	ctx context.Context,
	pro *oauth.Proposal,
) (*oauth.Issuance, error) {
	handle := pro.Get("handle")
	if handle == "" {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidRequest,
			Description: "missing handle",
		}
	}

	assertion := pro.Get("assertion")
	if assertion == "" {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidRequest,
			Description: "missing assertion",
		}
	}

	scope := pro.Get("scope")
	if scope != "" && !oauth.CanUseScope(pro.Client, scope) {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidScope,
			Description: "scope is not allowed for client",
		}
	}

	out, err := g.s.passkeys.FinishLogin(ctx, handle, []byte(assertion))
	if err != nil {
		return nil, &oauth.Error{
			Status:      http.StatusInternalServerError,
			Code:        oauth.ErrorCodeServerError,
			Description: "failed to finish login ceremony",
			Cause:       err,
		}
	}

	switch out.Status {
	case passkey.StatusInvalid:
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidGrant,
			Description: "invalid or expired handle",
		}
	case passkey.StatusRejected:
		pro.Logger.Debug(
			ctx,
			"WebAuthn assertion rejected",
			log.Err(out.Reason),
		)
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidGrant,
			Description: "assertion verification failed",
		}
	}

	id, err := uuid.Parse(out.Owner)
	if err != nil {
		return nil, &oauth.Error{
			Status:      http.StatusInternalServerError,
			Code:        oauth.ErrorCodeServerError,
			Description: "malformed ceremony owner",
			Cause:       err,
		}
	}

	return &oauth.Issuance{
		Subject:     id,
		Scope:       scope,
		Refreshable: true,
	}, nil
}

// webAuthnPrompt is the client-facing prompt a WebAuthn step returns: the
// assertion options the authenticator signs and the ceremony's lifetime.
type webAuthnPrompt struct {
	// Options are the WebAuthn assertion options for the authenticator.
	Options any `json:"options"`
	// ExpiresIn is the remaining lifetime of the ceremony in seconds.
	ExpiresIn int64 `json:"expires_in"`
}

// webAuthnStep is a [flow.Step] that confirms the login's subject with a
// passkey assertion.
type webAuthnStep struct {
	id string
	s  *Server
}

var _ flow.Step = (*webAuthnStep)(nil)

// ID implements [flow.Step].
func (w *webAuthnStep) ID() string { return w.id }

// handle derives the per-step ceremony handle from the outer flow handle. The
// flow handle is high-entropy, so the derived value is too.
func (w *webAuthnStep) handle(flowHandle string) string {
	return flowHandle + ":" + w.id
}

// Begin implements [flow.Step]: it starts a discoverable-login ceremony keyed
// on the derived handle and returns the assertion options to sign.
func (w *webAuthnStep) Begin(
	ctx context.Context,
	_ *flow.Transaction,
	handle string,
) (any, error) {
	options, expiresIn, err := w.s.passkeys.StartLogin(ctx, w.handle(handle))
	if err != nil {
		return nil, err
	}
	return webAuthnPrompt{Options: options, ExpiresIn: expiresIn}, nil
}

// Verify implements [flow.Step]: it finishes the ceremony and requires the
// asserted account to match the login's subject.
//
// A WebAuthn challenge is single use, so a failed or mismatched assertion burns
// the ceremony and fails the step (the client restarts the login) rather than
// retrying against a spent challenge.
func (w *webAuthnStep) Verify(
	ctx context.Context,
	t *flow.Transaction,
	handle string,
	in flow.Input,
) (flow.Verdict, error) {
	out, err := w.s.passkeys.FinishLogin(ctx, w.handle(handle), in.Raw)
	if err != nil {
		return 0, err
	}
	if !out.OK() {
		return flow.VerdictFail, nil
	}
	// The passkey must belong to the subject the login already identified, so a
	// valid assertion for another account cannot complete this login.
	if out.Owner != t.Owner {
		return flow.VerdictFail, nil
	}
	return flow.VerdictOK, nil
}

// Act implements [flow.Step]: a WebAuthn ceremony supports no out-of-band
// actions.
func (w *webAuthnStep) Act(
	_ context.Context,
	_ *flow.Transaction,
	_ string,
	_ flow.Action,
) (any, error) {
	return nil, fmt.Errorf(
		"%w: webauthn step supports no actions",
		flow.ErrRejected,
	)
}

// WebAuthn returns a [flow.Step] that confirms the login's subject with a
// passkey assertion. It is intended as a step-up factor after the subject is
// identified; the presented passkey must belong to that subject.
//
// It panics if id is empty or passkey support is not enabled via
// [WithPasskeys].
func (b Steps) WebAuthn(id string) flow.Step {
	if id == "" {
		panic("step ID is required")
	}
	if b.s.passkeys == nil {
		panic("passkey support is not enabled")
	}
	return &webAuthnStep{id: id, s: b.s}
}
