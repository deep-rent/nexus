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

package oauth

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"time"

	"uuid"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/nexus/router"
	"github.com/deep-rent/nexus/valid"
)

// WebAuthnCredential is a passkey credential record as verified and
// consumed by the underlying WebAuthn implementation. Store implementations
// should treat it as an opaque, JSON-serializable blob keyed by its ID
// field; see [SubjectStore.CreateWebAuthnCredential].
type WebAuthnCredential = webauthn.Credential

// DefaultWebAuthnSessionLifetime is the validity period of a WebAuthn
// ceremony session, i.e. the time a client may take between requesting
// ceremony options and submitting the authenticator's response.
const DefaultWebAuthnSessionLifetime = 5 * time.Minute

// WebAuthnConfig carries the relying party settings for passkey support,
// activated via [WithWebAuthn].
type WebAuthnConfig struct {
	// RPID is the relying party identifier: the effective domain that
	// passkeys are scoped to (e.g., "example.com"). Native apps must be
	// associated with this domain (apple-app-site-association on iOS,
	// assetlinks.json on Android) to use the same passkeys. Required.
	RPID string
	// RPDisplayName is the human-palatable relying party name shown by
	// authenticators during ceremonies. Required.
	RPDisplayName string
	// RPOrigins lists the origins allowed to answer challenges. Web clients
	// appear as regular origins (e.g., "https://app.example.com"); Android
	// apps appear as "android:apk-key-hash:..." origins and must be listed
	// explicitly. Required.
	RPOrigins []string
	// SessionLifetime overrides [DefaultWebAuthnSessionLifetime].
	SessionLifetime time.Duration
}

// webAuthnSupport holds the resolved passkey settings of a [Server].
type webAuthnSupport struct {
	handle          *webauthn.WebAuthn
	sessionLifetime time.Duration
}

// WithWebAuthn enables passkey support.
//
// Once enabled, [Server.Mount] registers the WebAuthn registration and
// login endpoints, and the token endpoint accepts the [GrantTypeWebAuthn]
// grant for clients that exchange a passkey assertion directly for tokens
// (native apps bypassing browser redirects).
//
// Registered credentials are required to be discoverable (resident keys)
// with user verification, so a passkey login is inherently multi-factor and
// does not go through the [WithOTP] OTP flow.
//
// It panics if the configuration is rejected by the underlying WebAuthn
// implementation, since relying party settings are startup configuration.
func WithWebAuthn(cfg WebAuthnConfig) Option {
	return func(s *Server) {
		handle, err := webauthn.New(&webauthn.Config{
			RPID:          cfg.RPID,
			RPDisplayName: cfg.RPDisplayName,
			RPOrigins:     cfg.RPOrigins,
			AuthenticatorSelection: protocol.AuthenticatorSelection{
				ResidentKey:      protocol.ResidentKeyRequirementRequired,
				UserVerification: protocol.VerificationRequired,
			},
		})
		if err != nil {
			panic("invalid WebAuthn configuration: " + err.Error())
		}
		s.webauthn = &webAuthnSupport{
			handle: handle,
			sessionLifetime: cmp.Or(
				cfg.SessionLifetime,
				DefaultWebAuthnSessionLifetime,
			),
		}
		s.grants[GrantTypeWebAuthn] = &webAuthnGrant{s}
	}
}

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

// webAuthnUser adapts a [Subject] and its stored credentials to the user
// model of the underlying WebAuthn implementation. The subject's UUID bytes
// double as the user handle, which discoverable credentials store on the
// authenticator and return with every assertion; this is what lets the
// login endpoints resolve the account without a username prompt.
type webAuthnUser struct {
	sub   Subject
	creds []WebAuthnCredential
}

func (u *webAuthnUser) WebAuthnID() []byte {
	id := u.sub.ID()
	return id[:]
}

func (u *webAuthnUser) WebAuthnName() string        { return u.sub.Username() }
func (u *webAuthnUser) WebAuthnDisplayName() string { return u.sub.Username() }

func (u *webAuthnUser) WebAuthnCredentials() []WebAuthnCredential {
	return u.creds
}

var _ webauthn.User = (*webAuthnUser)(nil)

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
		s.logger.DebugContext(
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

// beginWebAuthnCeremony persists the ceremony state under a fresh handle
// and returns the handle together with the client-side options.
func (s *Server) beginWebAuthnCeremony(
	e *router.Exchange,
	ceremony WebAuthnCeremony,
	subjectID uuid.UUID,
	options any,
	data *webauthn.SessionData,
) error {
	handle, err := s.generateWebAuthnHandle(e.Context())
	if err != nil {
		return router.ServerError("failed to generate handle", err)
	}

	raw, err := json.Marshal(data)
	if err != nil {
		return router.ServerError("failed to serialize ceremony state", err)
	}

	if err := s.sessions.CreateWebAuthnSession(e.Context(), WebAuthnSession{
		Handle:    NewDigest(handle),
		Ceremony:  ceremony,
		SubjectID: subjectID,
		Data:      raw,
		ExpiresAt: s.now().Add(s.webauthn.sessionLifetime).Unix(),
	}); err != nil {
		return router.ServerError("failed to store ceremony session", err)
	}

	return e.JSON(http.StatusOK, WebAuthnOptionsResponse{
		Handle:    handle,
		ExpiresIn: int64(s.webauthn.sessionLifetime.Seconds()),
		Options:   options,
	})
}

// takeWebAuthnSession claims the ceremony session bound to the given handle
// for a single finish attempt: it loads the session, checks that it matches
// the expected ceremony and has not expired, and deletes it atomically so a
// concurrent attempt cannot claim it again. Failed finishes deliberately
// burn the session; the client must begin a fresh ceremony.
//
// It returns nil data (with a nil error) when the handle is unknown,
// expired, of the wrong ceremony, or already claimed. It returns an error
// only if storage access or state deserialization fails.
func (s *Server) takeWebAuthnSession(
	ctx context.Context,
	handle string,
	ceremony WebAuthnCeremony,
) (WebAuthnSession, *webauthn.SessionData, error) {
	digest := NewDigest(handle)

	sess, err := s.sessions.GetWebAuthnSession(ctx, digest)
	if err != nil {
		return sess, nil, err
	}

	if sess.Handle == "" ||
		sess.Ceremony != ceremony ||
		(sess.ExpiresAt != 0 && s.now().Unix() > sess.ExpiresAt) {
		return sess, nil, nil
	}

	deleted, err := s.sessions.DeleteWebAuthnSession(ctx, digest)
	if err != nil {
		return sess, nil, err
	}
	if !deleted {
		return sess, nil, nil
	}

	var data webauthn.SessionData
	if err := json.Unmarshal(sess.Data, &data); err != nil {
		return sess, nil, err
	}

	return sess, &data, nil
}

// verifyWebAuthnAssertion validates a discoverable-credential assertion
// against the claimed ceremony state, resolves the asserting subject from
// the user handle, and persists the updated credential record (signature
// counter and backup flags).
//
// The first returned error (reject) reports why the assertion was refused
// and must translate into an authentication failure; the second (fail)
// reports a storage problem and must translate into a server error.
func (s *Server) verifyWebAuthnAssertion(
	ctx context.Context,
	data *webauthn.SessionData,
	credential []byte,
) (sub Subject, reject, fail error) {
	parsed, err := protocol.ParseCredentialRequestResponseBody(
		bytes.NewReader(credential),
	)
	if err != nil {
		return nil, err, nil
	}

	// Storage failures inside the lookup callback must not masquerade as
	// verification failures, so they are captured out-of-band.
	var lookupErr error
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		if len(userHandle) != len(uuid.UUID{}) {
			return nil, errors.New("malformed user handle")
		}
		id := uuid.UUID(userHandle)

		subject, err := s.subjects.GetSubject(ctx, id)
		if err != nil {
			lookupErr = err
			return nil, err
		}
		if subject == nil {
			return nil, errors.New("unknown subject")
		}

		creds, err := s.subjects.GetWebAuthnCredentials(ctx, id)
		if err != nil {
			lookupErr = err
			return nil, err
		}

		sub = subject
		return &webAuthnUser{sub: subject, creds: creds}, nil
	}

	cred, err := s.webauthn.handle.ValidateDiscoverableLogin(
		handler,
		*data,
		parsed,
	)
	if lookupErr != nil {
		return nil, nil, lookupErr
	}
	if err != nil {
		return nil, err, nil
	}

	if cred.Authenticator.CloneWarning {
		return nil, errors.New(
			"signature counter regressed; authenticator may be cloned",
		), nil
	}

	// The updated record carries the new signature counter; failing to
	// persist it would blind future clone detection, so the login fails
	// closed.
	if err := s.subjects.UpdateWebAuthnCredential(
		ctx,
		sub.ID(),
		*cred,
	); err != nil {
		return nil, nil, err
	}

	return sub, nil, nil
}

// WebAuthnRegisterOptions begins a passkey registration ceremony for an
// authenticated subject.
//
// The subject is identified via the session cookie or a Bearer access
// token; see [Server.WebAuthnRegister] for the accompanying finish step.
// The returned options exclude already registered credentials, require a
// discoverable credential, and demand user verification.
func (s *Server) WebAuthnRegisterOptions(e *router.Exchange) error {
	if s.webauthn == nil {
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

	creds, err := s.subjects.GetWebAuthnCredentials(e.Context(), sub.ID())
	if err != nil {
		return router.ServerError("failed to retrieve credentials", err)
	}

	creation, data, err := s.webauthn.handle.BeginRegistration(
		&webAuthnUser{sub: sub, creds: creds},
		webauthn.WithExclusions(
			webauthn.Credentials(creds).CredentialDescriptors(),
		),
	)
	if err != nil {
		return router.ServerError("failed to begin registration", err)
	}

	return s.beginWebAuthnCeremony(
		e,
		WebAuthnCeremonyRegistration,
		sub.ID(),
		creation,
		data,
	)
}

// WebAuthnRegister finishes a passkey registration ceremony by verifying
// the authenticator's attestation response and persisting the new
// credential via [SubjectStore.CreateWebAuthnCredential].
//
// It expects a [WebAuthnRegistrationRequest] carrying the handle returned
// by [Server.WebAuthnRegisterOptions] and must be called by the same
// subject that began the ceremony. Ceremony sessions are single use: any
// finish attempt, successful or not, burns the handle.
func (s *Server) WebAuthnRegister(e *router.Exchange) error {
	if s.webauthn == nil {
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

	sess, data, err := s.takeWebAuthnSession(
		e.Context(),
		req.Handle,
		WebAuthnCeremonyRegistration,
	)
	if err != nil {
		return router.ServerError("failed to claim ceremony session", err)
	}
	if data == nil || sess.SubjectID != sub.ID() {
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "invalid or expired handle",
		}
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(
		bytes.NewReader(req.Credential),
	)
	if err != nil {
		return &router.Error{
			Status:      http.StatusBadRequest,
			Reason:      router.ReasonValidationFailed,
			Description: "malformed credential",
		}
	}

	cred, err := s.webauthn.handle.CreateCredential(
		&webAuthnUser{sub: sub},
		*data,
		parsed,
	)
	if err != nil {
		s.logger.DebugContext(
			e.Context(),
			"WebAuthn attestation rejected",
			log.Err(err),
		)
		return &router.Error{
			Status:      http.StatusBadRequest,
			Reason:      router.ReasonValidationFailed,
			Description: "credential verification failed",
		}
	}

	if err := s.subjects.CreateWebAuthnCredential(
		e.Context(),
		sub.ID(),
		req.Name,
		*cred,
	); err != nil {
		return router.ServerError("failed to store credential", err)
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
// cookie) or via the [GrantTypeWebAuthn] token grant (native apps
// exchanging the assertion directly for tokens).
func (s *Server) WebAuthnLoginOptions(e *router.Exchange) error {
	if s.webauthn == nil {
		e.Status(http.StatusNotFound)
		return nil
	}

	assertion, data, err := s.webauthn.handle.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return router.ServerError("failed to begin login", err)
	}

	return s.beginWebAuthnCeremony(
		e,
		WebAuthnCeremonyLogin,
		uuid.Nil(),
		assertion,
		data,
	)
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
	if s.webauthn == nil {
		e.Status(http.StatusNotFound)
		return nil
	}

	var req WebAuthnLoginRequest
	if err := e.BindJSON(&req); err != nil {
		return err
	}

	_, data, err := s.takeWebAuthnSession(
		e.Context(),
		req.Handle,
		WebAuthnCeremonyLogin,
	)
	if err != nil {
		return router.ServerError("failed to claim ceremony session", err)
	}
	if data == nil {
		s.penalize(s.addr(e))
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "invalid or expired handle",
		}
	}

	sub, reject, fail := s.verifyWebAuthnAssertion(
		e.Context(),
		data,
		req.Credential,
	)
	if fail != nil {
		return router.ServerError("failed to verify assertion", fail)
	}
	if reject != nil {
		s.penalize(s.addr(e))
		s.logger.DebugContext(
			e.Context(),
			"WebAuthn assertion rejected",
			log.Err(reject),
		)
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "assertion verification failed",
		}
	}

	if err := s.session(e, sub); err != nil {
		return err
	}

	e.NoContent()

	return nil
}

// webAuthnGrant implements the custom [GrantTypeWebAuthn] grant. It lets a
// client exchange a passkey assertion directly for tokens, bypassing the
// browser-bound authorization code flow. The client obtains ceremony
// options from [Server.WebAuthnLoginOptions], performs the platform passkey
// ceremony, and submits the resulting assertion to the token endpoint:
//
//	grant_type=urn:ietf:params:oauth:grant-type:webauthn
//	handle=...    (ceremony reference from the options endpoint)
//	assertion=... (JSON-encoded PublicKeyCredential)
//	scope=...     (optional)
//
// The grant is registered automatically by [WithWebAuthn]; clients must
// additionally be allowed to use it via [Client.CanUseGrant].
type webAuthnGrant struct {
	s *Server
}

var _ Grant = (*webAuthnGrant)(nil)

// Type implements the [Grant] interface.
func (g *webAuthnGrant) Type() GrantType { return GrantTypeWebAuthn }

// Authorize implements the [Grant] interface.
func (g *webAuthnGrant) Authorize(
	ctx context.Context,
	pro *Proposal,
) (*Issuance, error) {
	handle := pro.Get("handle")
	if handle == "" {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "missing handle",
		}
	}

	assertion := pro.Get("assertion")
	if assertion == "" {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "missing assertion",
		}
	}

	scope := pro.Get("scope")
	if scope != "" && !canUseScope(pro.Client, scope) {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidScope,
			Description: "scope is not allowed for client",
		}
	}

	_, data, err := g.s.takeWebAuthnSession(
		ctx,
		handle,
		WebAuthnCeremonyLogin,
	)
	if err != nil {
		return nil, pro.ServerError("failed to claim ceremony session", err)
	}
	if data == nil {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "invalid or expired handle",
		}
	}

	sub, reject, fail := g.s.verifyWebAuthnAssertion(
		ctx,
		data,
		[]byte(assertion),
	)
	if fail != nil {
		return nil, pro.ServerError("failed to verify assertion", fail)
	}
	if reject != nil {
		pro.Logger.DebugContext(
			ctx,
			"WebAuthn assertion rejected",
			log.Err(reject),
		)
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "assertion verification failed",
		}
	}

	return &Issuance{
		Subject:     sub.ID(),
		Scope:       scope,
		Refreshable: true,
	}, nil
}
