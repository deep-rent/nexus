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
	"context"
	"fmt"
	"net/http"

	"uuid"

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/nexus/oauth/otp"
	"github.com/deep-rent/nexus/router"
)

// otpPurpose namespaces two-factor login challenges within the challenge store.
const otpPurpose = "2fa"

// Default values applied by [New] for the optional OTP-related [Config] fields.
const (
	// DefaultOTPCodeLength is the number of digits in a one-time password.
	DefaultOTPCodeLength = otp.DefaultLength
	// DefaultOTPLifetime is the validity period of a two-factor login
	// challenge.
	DefaultOTPLifetime = otp.DefaultLifetime
	// DefaultOTPMaxAttempts is the number of failed confirmation attempts
	// after which a challenge is burned.
	DefaultOTPMaxAttempts = otp.DefaultMaxAttempts
	// DefaultOTPMaxResends is the number of times the one-time password of a
	// single challenge may be redelivered.
	DefaultOTPMaxResends = otp.DefaultMaxResends
)

// otpStore adapts the server's [SessionStore] to the [otp.Store] interface, so
// existing SessionStore implementations back the challenge engine unchanged.
//
// Every challenge in this store belongs to a single purpose, injected on read
// because [OTPChallenge] does not persist it. The engine's
// [otp.Challenge.MethodID] is likewise not persisted: the server selects the
// delivery method per request from the subject's current enrollment.
type otpStore struct {
	sessions SessionStore
	purpose  string
}

var _ otp.Store = otpStore{}

// Create implements [otp.Store].
func (a otpStore) Create(ctx context.Context, c otp.Challenge) error {
	oc, err := a.toChallenge(c)
	if err != nil {
		return err
	}
	return a.sessions.CreateOTPChallenge(ctx, oc)
}

// Get implements [otp.Store].
func (a otpStore) Get(
	ctx context.Context,
	id string,
) (otp.Challenge, bool, error) {
	oc, err := a.sessions.GetOTPChallenge(ctx, Digest(id))
	if err != nil {
		return otp.Challenge{}, false, err
	}
	// SessionStore reports an absent or expired challenge as the zero value.
	if oc.Challenge == "" {
		return otp.Challenge{}, false, nil
	}
	return otp.Challenge{
		ID:        string(oc.Challenge),
		Code:      string(oc.Code),
		Owner:     oc.SubjectID.String(),
		Purpose:   a.purpose,
		ExpiresAt: oc.ExpiresAt,
		Attempts:  oc.Attempts,
		Resends:   oc.Resends,
	}, true, nil
}

// Update implements [otp.Store].
func (a otpStore) Update(ctx context.Context, c otp.Challenge) error {
	oc, err := a.toChallenge(c)
	if err != nil {
		return err
	}
	return a.sessions.UpdateOTPChallenge(ctx, oc)
}

// Delete implements [otp.Store].
func (a otpStore) Delete(ctx context.Context, id string) (bool, error) {
	return a.sessions.DeleteOTPChallenge(ctx, Digest(id))
}

// toChallenge maps an engine challenge onto the stored shape, parsing the owner
// back into a subject ID.
func (a otpStore) toChallenge(c otp.Challenge) (OTPChallenge, error) {
	sid, err := uuid.Parse(c.Owner)
	if err != nil {
		return OTPChallenge{}, fmt.Errorf("invalid challenge owner: %w", err)
	}
	return OTPChallenge{
		Challenge: Digest(c.ID),
		SubjectID: sid,
		Code:      Digest(c.Code),
		Attempts:  c.Attempts,
		Resends:   c.Resends,
		ExpiresAt: c.ExpiresAt,
	}, nil
}

// selectMethod returns the enrolled method with the given ID, or the default
// (first) method when id is empty. ok is false when no method matches.
func selectMethod(sf *SecondFactor, id string) (otp.Method, bool) {
	if sf == nil || len(sf.Methods) == 0 {
		return otp.Method{}, false
	}
	if id == "" {
		return sf.Methods[0], true
	}
	for _, m := range sf.Methods {
		if m.ID == id {
			return m, true
		}
	}
	return otp.Method{}, false
}

// methodInfos projects enrolled methods to their client-facing descriptions.
// It returns nil for a single method, since there is nothing to pick between.
func methodInfos(sf *SecondFactor) []MethodInfo {
	if len(sf.Methods) < 2 {
		return nil
	}
	infos := make([]MethodInfo, len(sf.Methods))
	for i, m := range sf.Methods {
		infos[i] = MethodInfo{ID: m.ID, Label: m.Label}
	}
	return infos
}

// beginOTPChallenge starts the second phase of a two-factor login: it mints a
// challenge, delivers a one-time password over the subject's default method,
// and returns the challenge to the client. The password has already been
// verified; no session is established until the code is confirmed via
// [Server.VerifyOTP].
func (s *Server) beginOTPChallenge(
	e *router.Exchange,
	sub Subject,
	sf *SecondFactor,
) error {
	m, ok := selectMethod(sf, "")
	if !ok {
		return router.ServerError("no second factor method is enrolled",
			fmt.Errorf("subject %s has an empty second factor", sub.ID()),
		)
	}

	handle, expiresIn, err := s.otp.Begin(
		e.Context(), otpPurpose, sub.ID().String(), m,
	)
	if err != nil {
		return router.ServerError("failed to deliver one-time password", err)
	}

	return e.JSON(http.StatusOK, OTPChallengeResponse{
		Challenge: handle,
		Method:    m.ID,
		Methods:   methodInfos(sf),
		ExpiresIn: expiresIn,
	})
}

// VerifyOTP confirms a pending two-factor login with the one-time password
// delivered to the resource owner, and establishes the session on success.
//
// It expects an [OTPVerificationRequest] carrying the challenge handle returned
// by [Server.Login] and the code received over the side channel. Challenges are
// single-use: after a successful confirmation, or once the attempt limit is
// exhausted, the challenge is deleted and the client must restart the login.
//
// One-time passwords are short enough to be guessed, so the endpoint is
// deliberately hostile to guessing: failed attempts are counted against both
// the challenge and the throttle, and the code comparison runs in constant time
// inside the challenge engine.
func (s *Server) VerifyOTP(e *router.Exchange) error {
	if s.otp == nil {
		e.Status(http.StatusNotFound)
		return nil
	}

	var req OTPVerificationRequest
	if err := e.BindJSON(&req); err != nil {
		return err
	}

	// Guesses are counted per challenge: an attacker holding one challenge
	// cannot spread guesses across it and a fresh allowance, and a legitimate
	// subject on a shared address is not locked out by someone else's failures.
	otpKey := scopeOTP + string(NewDigest(req.Challenge))
	if s.throttled(e, otpKey) {
		return &router.Error{
			Status:      http.StatusTooManyRequests,
			Reason:      router.ReasonRateLimit,
			Description: "too many failed attempts; try again later",
		}
	}

	out, err := s.otp.Verify(e.Context(), otpPurpose, req.Challenge, req.Code)
	if err != nil {
		return router.ServerError("failed to verify challenge", err)
	}

	// The rejection is deliberately uniform: it does not reveal whether the
	// challenge never existed, expired, or was burned by too many attempts.
	invalid := &router.Error{
		Status:      http.StatusUnauthorized,
		Reason:      auth.ReasonAuthenticationFailed,
		Description: "invalid or expired challenge",
	}

	if out.Status != otp.StatusOK {
		s.penalize(otpKey, s.addr(e))
		if out.Status == otp.StatusWrongCode {
			return &router.Error{
				Status:      http.StatusUnauthorized,
				Reason:      auth.ReasonAuthenticationFailed,
				Description: "invalid code",
			}
		}
		return invalid
	}

	// The code is proven; drop any penalty from earlier attempts.
	s.clear(otpKey)

	id, err := uuid.Parse(out.Owner)
	if err != nil {
		return router.ServerError("invalid challenge owner", err)
	}

	sub, err := s.subjects.GetSubject(e.Context(), id)
	if err != nil {
		return router.ServerError("failed to lookup subject", err)
	}
	if sub == nil {
		// The subject vanished between password verification and code
		// confirmation (e.g., account deletion).
		return invalid
	}

	if err := s.session(e, sub); err != nil {
		return err
	}

	e.NoContent()

	return nil
}

// ResendOTP redelivers the one-time password for a pending two-factor login,
// optionally over a different enrolled method.
//
// It expects an [OTPResendRequest] carrying the challenge handle returned by
// [Server.Login] and an optional method ID to switch channels. A fresh code
// replaces the previous one, but the challenge itself — its handle, expiry, and
// attempt count — remains unchanged, so resending cannot keep a login pending
// forever or reset the guess budget. The number of resends per challenge is
// capped by [Config.OTPMaxResends], because every delivery costs money and
// unsolicited deliveries spam the subject.
func (s *Server) ResendOTP(e *router.Exchange) error {
	if s.otp == nil {
		e.Status(http.StatusNotFound)
		return nil
	}

	var req OTPResendRequest
	if err := e.BindJSON(&req); err != nil {
		return err
	}

	otpKey := scopeOTP + string(NewDigest(req.Challenge))
	if s.throttled(e, otpKey) {
		return &router.Error{
			Status:      http.StatusTooManyRequests,
			Reason:      router.ReasonRateLimit,
			Description: "too many failed attempts; try again later",
		}
	}

	invalid := &router.Error{
		Status:      http.StatusUnauthorized,
		Reason:      auth.ReasonAuthenticationFailed,
		Description: "invalid or expired challenge",
	}

	// Resolve the owner so the enrollment can be re-read: a change of address
	// or channel mid-login then takes effect immediately.
	owner, ok, err := s.otp.Peek(e.Context(), otpPurpose, req.Challenge)
	if err != nil {
		return router.ServerError("failed to retrieve challenge", err)
	}
	if !ok {
		s.penalize(otpKey, s.addr(e))
		return invalid
	}

	id, err := uuid.Parse(owner)
	if err != nil {
		return router.ServerError("invalid challenge owner", err)
	}

	sf, err := s.subjects.GetSecondFactor(e.Context(), id)
	if err != nil {
		return router.ServerError("failed to lookup second factor", err)
	}
	if sf == nil {
		// Enrollment was revoked mid-login; the pending challenge can never be
		// completed, so cancel it.
		if _, cerr := s.otp.Cancel(e.Context(), req.Challenge); cerr != nil {
			s.logger.ErrorContext(
				e.Context(),
				"Failed to cancel orphaned challenge",
				log.Err(cerr),
			)
		}
		return invalid
	}

	m, ok := selectMethod(sf, req.Method)
	if !ok {
		return &router.Error{
			Status:      http.StatusBadRequest,
			Reason:      router.ReasonValidationFailed,
			Description: "unknown delivery method",
		}
	}

	out, err := s.otp.Resend(e.Context(), otpPurpose, req.Challenge, m)
	if err != nil {
		return router.ServerError("failed to deliver one-time password", err)
	}

	switch out.Status {
	case otp.StatusOK:
		return e.JSON(http.StatusOK, OTPChallengeResponse{
			Challenge: req.Challenge,
			Method:    m.ID,
			Methods:   methodInfos(sf),
			ExpiresIn: out.ExpiresIn,
		})
	case otp.StatusResendLimit:
		return &router.Error{
			Status:      http.StatusTooManyRequests,
			Reason:      router.ReasonRateLimit,
			Description: "resend limit reached",
		}
	default:
		s.penalize(otpKey, s.addr(e))
		return invalid
	}
}
