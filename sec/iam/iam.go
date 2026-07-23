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

	"uuid"

	"github.com/deep-rent/nexus/dat/valid"
	"github.com/deep-rent/nexus/sec/iam/flow"
	"github.com/deep-rent/nexus/sec/iam/idp"
	"github.com/deep-rent/nexus/sec/iam/oauth"
	"github.com/deep-rent/nexus/sec/iam/otp"
	"github.com/deep-rent/nexus/sec/iam/passkey"
	"github.com/deep-rent/nexus/sec/iam/session"
	"github.com/deep-rent/nexus/sec/iam/trust"
)

// Subject represents an authenticated resource owner, typically a user.
//
// Implementations wrap the primary key and permission set. They are managed
// via [SubjectStore].
type Subject interface {
	// ID returns the unique identifier for the subject.
	ID() uuid.UUID
	// Username returns the unique, human-readable identifier the subject
	// logs in with (e.g., an email address or handle). It labels the
	// subject's account in contexts where the raw UUID would be meaningless
	// to humans, such as the account picker of a passkey ceremony.
	Username() string
	// Roles returns the list of roles assigned to the subject, used to populate
	// the roles claim in access tokens.
	Roles() []string
}

// Channel is the client-facing description of an enrolled [otp.Method],
// returned in a login flow prompt so a client can present a channel picker. It
// never carries a secret or a raw destination.
type Channel struct {
	// ID is the stable identifier used to select this method on resend.
	ID string `json:"id"`
	// Label is an optional human-facing hint, such as a masked address or phone
	// number.
	Label string `json:"label,omitzero"`
}

// SubjectStore provides identity resolution and credential verification for
// resource owners.
//
// It is used by the [Server] to authenticate subjects during the login flow
// and to resolve identities during authorization and token issuance. Session
// state lives elsewhere, in [Stores.Sessions].
type SubjectStore interface {
	// Authenticate validates subject credentials.
	//
	// If credentials are valid, it must return the subject and nil.
	// If authentication fails (e.g., wrong password), it must return nil and
	// nil. It should return an error only if the underlying storage lookup
	// fails.
	//
	// Implementations should not hand-roll password verification; the
	// [github.com/deep-rent/nexus/sec/pass] package stores self-describing
	// JSON records and resolves the hashing algorithm dynamically. Verify
	// the password and, while the plaintext is still at hand, transparently
	// upgrade hashes that predate the current hashing configuration:
	//
	//	func (s *store) Authenticate(
	//	  ctx context.Context,
	//	  username, password string,
	//	) (iam.Subject, error) {
	//	  sub, record, err := s.lookup(ctx, username)
	//	  if err != nil || sub == nil {
	//	    return nil, err
	//	  }
	//	  ok, err := s.hasher.Verify(record, password)
	//	  if err != nil || !ok {
	//	    return nil, err // nil, nil on a wrong password
	//	  }
	//	  // The password is proven; converge its stored hash to the
	//	  // strongest configuration without a mass reset.
	//	  if stale, _ := s.hasher.Outdated(record); stale {
	//	    if record, err = s.hasher.Hash(password); err == nil {
	//	      s.updateRecord(ctx, sub.ID(), record)
	//	    }
	//	  }
	//	  return sub, nil
	//	}
	Authenticate(
		ctx context.Context,
		username, password string,
	) (Subject, error)
	// GetSubject retrieves a subject by their unique ID.
	//
	// If the user is found, it must return the subject and nil.
	// If the user is not found, it must return nil and nil.
	// It should return an error only if the storage lookup fails.
	GetSubject(ctx context.Context, id uuid.UUID) (Subject, error)
	// GetSubjectByUsername resolves a subject by their username without
	// verifying any credential.
	//
	// If the user is found, it must return the subject and nil.
	// If the user is not found, it must return nil, nil. It should return an
	// error only if the storage lookup fails.
	//
	// The method is only consulted when passwordless login is enabled via
	// [WithPasswordless]; other servers may return nil, nil. Because it
	// identifies a subject without authenticating them, callers must treat the
	// result as a claim proven only once the login flow completes.
	GetSubjectByUsername(ctx context.Context, username string) (Subject, error)
	// GetSubjectByExternalID retrieves a subject linked to an external
	// identity provider.
	//
	// This is used for social login flows. If no local subject is linked to
	// the external ID, it returns nil, nil (allowing for Just-In-Time
	// provisioning if the implementation chooses to do so).
	GetSubjectByExternalID(
		ctx context.Context,
		provider string, identity idp.Claimant,
	) (Subject, error)
}

// Stores bundles the persistence backends for every ephemeral artifact the
// [Server] manages. The token-issuance stores are embedded as
// [oauth.TokenStores]; the rest back the login machinery: one-time password
// challenges, login flow transactions, device trust records, and WebAuthn
// ceremony sessions.
//
// All records are keyed by digests — the server hashes every bearer secret
// before it crosses a store boundary — and follow the same basic CRUD
// contract. A single generic backend can therefore be instantiated per
// artifact type; the stores enabled by the server's options must be non-nil
// (see [New]).
type Stores struct {
	oauth.TokenStores

	// Sessions persists login sessions: the digest-keyed mapping from a
	// session key to the authenticated subject. Always required, since the
	// login endpoints are always mounted.
	Sessions session.Store
	// Challenges persists one-time password challenges for the login flow
	// steps built via [Steps.OTP]. Required with [WithFlow].
	Challenges otp.Store
	// Flows persists multi-step login transactions. Required with
	// [WithFlow].
	Flows flow.Store
	// Trust persists remember-me device trust records. Required with
	// [WithFlow], whose remembered logins enroll devices.
	Trust trust.Store
	// Ceremonies persists pending WebAuthn ceremony sessions. Required with
	// [WithPasskeys].
	Ceremonies passkey.Store
	// Credentials persists registered passkey credentials. Unlike its
	// siblings it holds durable identity data rather than ephemeral
	// artifacts. Required with [WithPasskeys].
	Credentials passkey.CredentialStore
}

// LoginRequest represents the payload for the resource owner login endpoint.
//
// It is consumed by [Server.Login] to authenticate a resource owner and
// initiate a secure session via the [SubjectStore.Authenticate] method.
type LoginRequest struct {
	// Username is the unique identifier (e.g., an email address or handle)
	// used by the resource owner to authenticate. This value is passed to
	// [SubjectStore.Authenticate] to resolve the [Subject].
	Username string `json:"username"`
	// Password is the secret credential provided by the resource owner.
	// It is used to verify the identity of the user during the login process.
	Password string `json:"password"`
	// Remember asks the server to remember the login: it persists the session
	// beyond the browser session and, on a device that completes any required
	// factors, trusts the device so later logins may skip them.
	Remember bool `json:"remember,omitzero"`
}

// Validate implements the [valid.Validatable] interface.
func (r *LoginRequest) Validate(v *valid.Validator) {
	v.NotEmpty("username", r.Username)
	v.NotEmpty("password", r.Password)
}

var _ valid.Validatable = (*LoginRequest)(nil)

// IdentifyRequest represents the payload for the passwordless login endpoint.
//
// It is consumed by [Server.Identify] to start a passwordless login: the
// subject is identified by username (without a credential) and the login flow
// then authenticates them through its factors.
type IdentifyRequest struct {
	// Username identifies the resource owner. It is not a credential; the flow
	// factors prove control of the account.
	Username string `json:"username"`
	// Remember asks the server to remember the login once the flow completes,
	// as in [LoginRequest].
	Remember bool `json:"remember,omitzero"`
}

// Validate implements the [valid.Validatable] interface.
func (r *IdentifyRequest) Validate(v *valid.Validator) {
	v.NotEmpty("username", r.Username)
}

var _ valid.Validatable = (*IdentifyRequest)(nil)

// FlowResponse is the payload returned by the login, continue, and action
// endpoints when a login requires a further authentication step.
//
// Instead of a session, the client receives a flow handle and a description of
// the active step. It must satisfy the step and confirm via
// [Server.Continue], or drive an out-of-band action (such as resending a code)
// via [Server.Action], carrying the same handle throughout.
type FlowResponse struct {
	// Handle is the opaque handle identifying the pending login. It is required
	// to continue or act on the flow.
	Handle string `json:"handle"`
	// Step is the identifier of the active step (e.g. "otp").
	Step string `json:"step"`
	// Prompt is the step-specific data the client needs to satisfy the step,
	// such as the available delivery channels and a code's remaining lifetime.
	// It is omitted when the step needs no such data.
	Prompt any `json:"prompt,omitzero"`
}

// ContinueRequest represents the payload for the login continue endpoint.
//
// It is consumed by [Server.Continue] to satisfy the active step of a pending
// login with the credential the resource owner supplied. The active step reads
// whichever field it expects: a code-based step (such as a one-time password)
// reads the code, while an assertion-based step (such as WebAuthn) reads
// the credential.
type ContinueRequest struct {
	// Handle is the flow handle returned by the login endpoint.
	Handle string `json:"handle"`
	// Code is the credential for a code-based step, such as a one-time
	// password.
	Code string `json:"code,omitzero"`
	// Credential is the structured credential for an assertion-based step,
	// such as a JSON-encoded WebAuthn assertion.
	Credential jsontext.Value `json:"credential,omitzero"`
}

// Validate implements the [valid.Validatable] interface.
func (r *ContinueRequest) Validate(v *valid.Validator) {
	v.NotEmpty("handle", r.Handle)
}

var _ valid.Validatable = (*ContinueRequest)(nil)

// ActionRequest represents the payload for the login action endpoint.
//
// It is consumed by [Server.Action] to drive an out-of-band operation on the
// active step of a pending login, such as resending a one-time password or
// switching the delivery channel.
type ActionRequest struct {
	// Handle is the flow handle returned by the login endpoint.
	Handle string `json:"handle"`
	// Action names the operation to run (e.g. [ActionResend]).
	Action string `json:"action"`
	// Channel optionally selects a different delivery channel (by
	// [Channel.ID]) for actions that support it, such as a resend.
	Channel string `json:"channel,omitzero"`
}

// Validate implements the [valid.Validatable] interface.
func (r *ActionRequest) Validate(v *valid.Validator) {
	v.NotEmpty("handle", r.Handle)
	v.NotEmpty("action", r.Action)
}

var _ valid.Validatable = (*ActionRequest)(nil)

// Path constants define the login-machinery endpoints managed by the
// [Server]. The token-machinery paths live in the oauth package (e.g.
// [oauth.PathToken]).
const (
	PathExternalCallback        = "/callback/{provider}"
	PathExternalLogin           = "/login/{provider}"
	PathLogin                   = "/login"
	PathLoginIdentify           = "/login/identify"
	PathLoginContinue           = "/login/continue"
	PathLoginAction             = "/login/action"
	PathLogout                  = "/logout"
	PathWebAuthnLogin           = "/webauthn/login"
	PathWebAuthnLoginOptions    = "/webauthn/login/options"
	PathWebAuthnRegister        = "/webauthn/register"
	PathWebAuthnRegisterOptions = "/webauthn/register/options"
)
