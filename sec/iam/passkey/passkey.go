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

// Package passkey implements the WebAuthn Relying Party role: registering
// passkey credentials and verifying passkey assertions.
//
// The [RelyingParty] is a transport-agnostic engine in the style of
// [github.com/deep-rent/nexus/sec/iam/otp.Challenger]: it runs the
// registration and login ceremonies over a digest-keyed [Store] of pending
// [Ceremony] state, resolves accounts through a [Directory], and persists
// [Credential] records through a [CredentialStore]. How handles and options
// travel to the client — HTTP endpoints, a token grant, a login flow step —
// is the caller's concern.
//
// Registered credentials are required to be discoverable (resident keys)
// with user verification, so a passkey login is inherently multi-factor: the
// authenticator both holds the credential and verifies its user. Logins are
// therefore account-discovering — the asserting account is resolved from the
// user handle embedded in the assertion, never from a username prompt.
//
// Ceremony state is single use: any finish attempt, successful or not, burns
// the handle, so a failed assertion cannot be retried against a spent
// challenge. Logical results are reported as an [Outcome]; Go errors are
// reserved for storage failures.
package passkey

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/iam/artifact"
	"github.com/deep-rent/nexus/sec/nonce"
)

// Credential is a passkey credential record as verified and consumed by the
// underlying WebAuthn implementation. Store implementations should treat it
// as an opaque, JSON-serializable blob keyed by its ID field; see
// [CredentialStore].
type Credential = webauthn.Credential

// Kind distinguishes the two ceremonies whose state a [Ceremony] tracks.
type Kind string

const (
	// KindRegistration marks a credential registration (attestation)
	// ceremony.
	KindRegistration Kind = "registration"
	// KindLogin marks an authentication (assertion) ceremony.
	KindLogin Kind = "login"
)

// Ceremony holds the server-side state of a WebAuthn ceremony between its
// begin and finish steps, most importantly the challenge the authenticator
// response must answer.
//
// The handle is the client's reference to the pending ceremony; the
// serialized state is produced and consumed by the engine and is opaque to
// the store.
type Ceremony struct {
	// ID is the digest of the client-facing handle and the storage key. The
	// plaintext handle never reaches the store.
	ID string `json:"id"`
	// Kind states which ceremony this state belongs to. A ceremony begun for
	// one kind cannot finish another.
	Kind Kind `json:"kind"`
	// Owner is an opaque reference to the account that began a registration
	// ceremony. It is empty for login ceremonies, where the account is only
	// discovered from the assertion itself.
	Owner string `json:"owner,omitzero"`
	// Data carries the serialized ceremony state. Implementations must
	// persist it verbatim.
	Data []byte `json:"data"`
	// ExpiresAt is the expiry as a Unix timestamp in seconds.
	ExpiresAt int64 `json:"expires_at"`
}

// Store persists pending ceremonies keyed by [Ceremony.ID]. See
// [artifact.Store] for the storage contract, notably the atomic deletion the
// engine relies on to make every ceremony single use.
type Store = artifact.Store[string, Ceremony]

// CredentialStore persists registered passkey credentials per account.
//
// Unlike the ceremony [Store], credentials are durable identity data: they
// live until the account holder removes them. Implementations should persist
// them as opaque records (e.g., JSON blobs keyed by owner and credential ID)
// and must not modify them.
type CredentialStore interface {
	// List returns every credential registered by the owner. An account
	// without any yields an empty slice. The error is reserved for storage
	// failures.
	List(ctx context.Context, owner string) ([]Credential, error)
	// Create stores a newly registered credential for the owner. The name is
	// an optional human-readable label chosen by the account holder (e.g.,
	// "MacBook Touch ID"); implementations may ignore it.
	Create(ctx context.Context, owner, name string, cred Credential) error
	// Update replaces a stored credential, keyed by the owner and the
	// credential's ID field. The engine calls it after every successful
	// assertion to persist the updated signature counter and backup flags,
	// which future assertions are validated against. Updating an absent
	// credential is a no-op.
	Update(ctx context.Context, owner string, cred Credential) error
}

// Account describes a credential-owning account to the engine.
//
// The handle is the WebAuthn user handle: an opaque byte string that
// discoverable credentials store on the authenticator and return with every
// assertion, which is what lets a login resolve the account without a
// username prompt. It must be stable and unique per account (e.g., the raw
// bytes of the account's UUID) and must not carry personal information.
type Account struct {
	// Handle is the WebAuthn user handle.
	Handle []byte
	// Owner is the opaque account reference used to key stored credentials
	// and returned in login outcomes (e.g. a subject ID).
	Owner string
	// Username is the human-palatable identifier shown by authenticators
	// during ceremonies, such as an email address.
	Username string
	// Credentials lists the account's registered credentials. It is consulted
	// during registration to exclude re-registering authenticators; logins
	// load credentials through the [Directory] instead.
	Credentials []Credential
}

// Directory resolves the account behind a WebAuthn user handle during a
// login ceremony.
type Directory interface {
	// Lookup returns the account owning the given user handle, including its
	// registered credentials. found is false when no such account exists;
	// the error is reserved for storage failures.
	Lookup(ctx context.Context, userHandle []byte) (Account, bool, error)
}

// Status is the logical result of finishing a ceremony. It is distinct from
// a Go error, which is reserved for storage failures the caller cannot
// recover from.
type Status int

const (
	// StatusOK indicates the ceremony finished successfully.
	StatusOK Status = iota
	// StatusInvalid indicates the ceremony handle is unknown, expired, of the
	// wrong kind, already claimed, or bound to another account. The reasons
	// are deliberately collapsed into one status so that callers cannot leak
	// which applies.
	StatusInvalid
	// StatusRejected indicates a live ceremony whose authenticator response
	// failed verification. The ceremony is burned; the client must begin a
	// fresh one.
	StatusRejected
)

// Outcome carries the result of finishing a ceremony.
type Outcome struct {
	// Status is the logical result.
	Status Status
	// Owner is the account reference the ceremony proved. It is set only
	// when [RelyingParty.FinishLogin] returns [StatusOK].
	Owner string
	// Credential is the verified credential record. On a finished
	// registration it is the newly created credential; on a finished login
	// it carries the updated signature counter and backup flags.
	Credential *Credential
	// Reason explains a [StatusRejected] outcome for the caller's logs. It
	// may carry verifier detail and must not reach the client.
	Reason error
}

// OK reports whether the outcome represents success.
func (o Outcome) OK() bool { return o.Status == StatusOK }

// RelyingParty runs the lifecycle of WebAuthn ceremonies — beginning them,
// persisting their state, and verifying the authenticator responses that
// finish them — over a [Store]. It is safe for concurrent use if its stores
// are.
type RelyingParty struct {
	rp          *webauthn.WebAuthn
	store       Store
	credentials CredentialStore
	directory   Directory
	lifetime    time.Duration
	hasher      *digest.Hasher
	handles     *nonce.Generator
	now         func() time.Time
}

// New creates a [RelyingParty] from the given configuration.
//
// It panics if the store, credential store, or directory is missing, or if
// the configuration is rejected by the underlying WebAuthn implementation —
// relying party settings are startup configuration, so misconfiguration is a
// programmer error.
func New(
	cfg Config,
	store Store,
	credentials CredentialStore,
	directory Directory,
	opts ...Option,
) *RelyingParty {
	switch {
	case store == nil:
		panic("ceremony store is required")
	case credentials == nil:
		panic("credential store is required")
	case directory == nil:
		panic("directory is required")
	}

	rp, err := webauthn.New(&webauthn.Config{
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

	p := &RelyingParty{
		rp:          rp,
		store:       store,
		credentials: credentials,
		directory:   directory,
		lifetime:    cmp.Or(cfg.Lifetime, DefaultLifetime),
		hasher:      digest.DefaultHasher,
		handles:     nonce.DefaultGenerator,
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Lifetime returns the configured ceremony lifetime.
func (p *RelyingParty) Lifetime() time.Duration { return p.lifetime }

// user adapts an [Account] to the user model of the underlying WebAuthn
// implementation.
type user struct {
	acct Account
}

func (u *user) WebAuthnID() []byte                { return u.acct.Handle }
func (u *user) WebAuthnName() string              { return u.acct.Username }
func (u *user) WebAuthnDisplayName() string       { return u.acct.Username }
func (u *user) WebAuthnCredentials() []Credential { return u.acct.Credentials }

var _ webauthn.User = (*user)(nil)

// BeginRegistration starts a credential registration ceremony for the
// account, persisting the ceremony state under a fresh handle.
//
// It returns the handle the client must echo back to
// [RelyingParty.FinishRegistration], the credential creation options for the
// client-side WebAuthn API (navigator.credentials.create or the platform
// equivalent), and the ceremony lifetime in seconds. The options exclude the
// account's already registered credentials, require a discoverable
// credential, and demand user verification.
func (p *RelyingParty) BeginRegistration(
	ctx context.Context,
	acct Account,
) (handle string, options any, expiresIn int64, err error) {
	creation, data, err := p.rp.BeginRegistration(
		&user{acct: acct},
		webauthn.WithExclusions(
			webauthn.Credentials(acct.Credentials).CredentialDescriptors(),
		),
	)
	if err != nil {
		return "", nil, 0, err
	}

	handle, err = p.handles.Draw(ctx)
	if err != nil {
		return "", nil, 0, err
	}
	if err := p.begin(
		ctx, handle, KindRegistration, acct.Owner, data,
	); err != nil {
		return "", nil, 0, err
	}
	return handle, creation, int64(p.lifetime.Seconds()), nil
}

// FinishRegistration verifies the authenticator's attestation response and
// persists the new credential for the account via [CredentialStore.Create],
// under the given optional human-readable name.
//
// The ceremony must have been begun by the same account; a handle begun for
// another account yields [StatusInvalid]. Ceremonies are single use: any
// finish attempt, successful or not, burns the handle. The error return is
// reserved for storage failures; all logical results are conveyed by the
// [Outcome].
func (p *RelyingParty) FinishRegistration(
	ctx context.Context,
	acct Account,
	name, handle string,
	response []byte,
) (Outcome, error) {
	data, err := p.take(ctx, handle, KindRegistration, acct.Owner)
	if err != nil {
		return Outcome{}, err
	}
	if data == nil {
		return Outcome{Status: StatusInvalid}, nil
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(
		bytes.NewReader(response),
	)
	if err != nil {
		return Outcome{Status: StatusRejected, Reason: err}, nil
	}

	cred, err := p.rp.CreateCredential(&user{acct: acct}, *data, parsed)
	if err != nil {
		return Outcome{Status: StatusRejected, Reason: err}, nil
	}

	if err := p.credentials.Create(ctx, acct.Owner, name, *cred); err != nil {
		return Outcome{}, err
	}

	return Outcome{Status: StatusOK, Credential: cred}, nil
}

// BeginLogin starts an account-discovering login ceremony, persisting the
// ceremony state under a fresh handle.
//
// It returns the handle the client must echo back to
// [RelyingParty.FinishLogin], the assertion options for the client-side
// WebAuthn API (navigator.credentials.get or the platform equivalent), and
// the ceremony lifetime in seconds. The options carry no credential
// allowlist; the account is discovered from the user handle embedded in the
// assertion.
func (p *RelyingParty) BeginLogin(
	ctx context.Context,
) (handle string, options any, expiresIn int64, err error) {
	handle, err = p.handles.Draw(ctx)
	if err != nil {
		return "", nil, 0, err
	}
	options, expiresIn, err = p.StartLogin(ctx, handle)
	if err != nil {
		return "", nil, 0, err
	}
	return handle, options, expiresIn, nil
}

// StartLogin begins a login ceremony under a caller-provided handle instead
// of a generated one, and otherwise behaves exactly like
// [RelyingParty.BeginLogin]. It lets a caller derive the handle
// deterministically — for example, a login step keying its ceremony on an
// outer flow handle so the client holds a single token.
//
// The handle MUST be unpredictable: the ceremony is only as unguessable as
// the handle it is keyed on. Deriving it from a high-entropy secret
// satisfies this.
func (p *RelyingParty) StartLogin(
	ctx context.Context,
	handle string,
) (options any, expiresIn int64, err error) {
	assertion, data, err := p.rp.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, 0, err
	}
	if err := p.begin(ctx, handle, KindLogin, "", data); err != nil {
		return nil, 0, err
	}
	return assertion, int64(p.lifetime.Seconds()), nil
}

// FinishLogin verifies a discoverable-credential assertion against the
// pending ceremony, resolves the asserting account from the user handle via
// the [Directory], and persists the updated credential record (signature
// counter and backup flags) via [CredentialStore.Update].
//
// A regressed signature counter (a cloned-authenticator indicator) rejects
// the assertion, and a failure to persist the updated record fails the login
// closed, since it would blind future clone detection. Ceremonies are single
// use: any finish attempt, successful or not, burns the handle. The error
// return is reserved for storage failures; all logical results are conveyed
// by the [Outcome], whose Owner reports the authenticated account.
func (p *RelyingParty) FinishLogin(
	ctx context.Context,
	handle string,
	response []byte,
) (Outcome, error) {
	data, err := p.take(ctx, handle, KindLogin, "")
	if err != nil {
		return Outcome{}, err
	}
	if data == nil {
		return Outcome{Status: StatusInvalid}, nil
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(
		bytes.NewReader(response),
	)
	if err != nil {
		return Outcome{Status: StatusRejected, Reason: err}, nil
	}

	// Storage failures inside the lookup callback must not masquerade as
	// verification failures, so they are captured out-of-band.
	var (
		lookupErr error
		owner     string
	)
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		acct, found, err := p.directory.Lookup(ctx, userHandle)
		if err != nil {
			lookupErr = err
			return nil, err
		}
		if !found {
			return nil, errors.New("unknown account")
		}
		owner = acct.Owner
		return &user{acct: acct}, nil
	}

	cred, err := p.rp.ValidateDiscoverableLogin(handler, *data, parsed)
	if lookupErr != nil {
		return Outcome{}, lookupErr
	}
	if err != nil {
		return Outcome{Status: StatusRejected, Reason: err}, nil
	}

	if cred.Authenticator.CloneWarning {
		return Outcome{Status: StatusRejected, Reason: errors.New(
			"signature counter regressed; authenticator may be cloned",
		)}, nil
	}

	// The updated record carries the new signature counter; failing to
	// persist it would blind future clone detection, so the login fails
	// closed.
	if err := p.credentials.Update(ctx, owner, *cred); err != nil {
		return Outcome{}, err
	}

	return Outcome{Status: StatusOK, Owner: owner, Credential: cred}, nil
}

// begin persists fresh ceremony state under the digest of the given handle.
func (p *RelyingParty) begin(
	ctx context.Context,
	handle string,
	kind Kind,
	owner string,
	data *webauthn.SessionData,
) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return p.store.Create(ctx, Ceremony{
		ID:        p.hasher.String(handle),
		Kind:      kind,
		Owner:     owner,
		Data:      raw,
		ExpiresAt: p.now().Add(p.lifetime).Unix(),
	})
}

// take claims the ceremony bound to the given handle for a single finish
// attempt: it loads the state, checks kind, owner, and expiry, and deletes
// it atomically so a concurrent attempt cannot claim it again.
//
// It returns nil data (with a nil error) when the handle is unknown,
// expired, mismatched, or already claimed. The error is reserved for storage
// access and state deserialization failures.
func (p *RelyingParty) take(
	ctx context.Context,
	handle string,
	kind Kind,
	owner string,
) (*webauthn.SessionData, error) {
	id := p.hasher.String(handle)

	c, found, err := p.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !found ||
		c.Kind != kind ||
		c.Owner != owner ||
		(c.ExpiresAt != 0 && p.now().Unix() > c.ExpiresAt) {
		return nil, nil
	}

	deleted, err := p.store.Delete(ctx, id)
	if err != nil {
		return nil, err
	}
	if !deleted {
		return nil, nil
	}

	var data webauthn.SessionData
	if err := json.Unmarshal(c.Data, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
