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
	"crypto/subtle"
	"fmt"
	"net/http"
	"time"

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/nexus/otp"
	"github.com/deep-rent/nexus/router"
)

// Default values applied by [New] for the optional OTP-related [Config]
// fields.
const (
	// DefaultOTPCodeLength is the number of digits in a one-time password.
	DefaultOTPCodeLength = otp.DefaultLength
	// DefaultOTPLifetime is the validity period of a two-factor login
	// challenge.
	DefaultOTPLifetime = 5 * time.Minute
	// DefaultOTPMaxAttempts is the number of failed confirmation attempts
	// after which a challenge is burned.
	DefaultOTPMaxAttempts = 5
	// DefaultOTPMaxResends is the number of times the one-time password of a
	// single challenge may be redelivered.
	DefaultOTPMaxResends = 3
)

// WithOTPChannel registers an [otp.Channel] for delivering one-time
// passwords under the given name, and thereby enables two-factor logins.
//
// The name connects enrollments to channels: a subject whose
// [SecondFactor.Channel] equals the name receives their codes through the
// registered channel. [SecondFactorChannelSMS] and
// [SecondFactorChannelEmail] are the conventional names for the adapters
// provided by the otp package, but any name may be used to plug in custom
// delivery mechanisms (e.g., push notifications or messenger bots):
//
//	s := oauth.New(cfg,
//	  oauth.WithOTPChannel(oauth.SecondFactorChannelSMS, otp.SMS(...)),
//	  oauth.WithOTPChannel("push", myPushChannel),
//	)
//
// Once at least one channel is registered, a successful password login of
// a subject with an enrolled [SecondFactor] (see
// [SubjectStore.GetSecondFactor]) no longer establishes a session directly.
// Instead, the server delivers a one-time password over the enrolled
// channel and returns an [OTPChallengeResponse]; the client completes the
// login via [Server.VerifyOTP]. [Server.Mount] registers the verification
// and resend endpoints only when a channel is present. The flow is tuned
// via the OTP-prefixed fields of [Config].
//
// It panics if the name is empty or the channel is nil, since both are
// startup configuration errors.
func WithOTPChannel(name SecondFactorChannel, ch otp.Channel) Option {
	return func(s *Server) {
		if name == "" {
			panic("channel name is required")
		}
		if ch == nil {
			panic("channel is required")
		}
		s.otpChannels[name] = ch
	}
}

// beginOTPChallenge starts the second phase of a two-factor login: it mints
// a challenge handle, delivers a one-time password to the subject over the
// enrolled channel, and returns the challenge to the client. The password
// has already been verified at this point; no session is established until
// the code is confirmed via [Server.VerifyOTP].
func (s *Server) beginOTPChallenge(
	e *router.Exchange,
	sub Subject,
	sf *SecondFactor,
) error {
	channel := s.otpChannels[sf.Channel]
	if channel == nil {
		return router.ServerError("second factor channel is not available",
			fmt.Errorf("no delivery channel configured for %q", sf.Channel),
		)
	}

	challenge, err := s.generateOTPChallenge(e.Context())
	if err != nil {
		return router.ServerError("failed to generate challenge", err)
	}

	code, err := s.generateOTPCode(e.Context())
	if err != nil {
		return router.ServerError("failed to generate one-time password",
			err,
		)
	}

	digest := NewDigest(challenge)

	if err := s.sessions.CreateOTPChallenge(e.Context(), OTPChallenge{
		Challenge: digest,
		SubjectID: sub.ID(),
		Code:      NewDigest(code),
		ExpiresAt: s.clock().Add(s.otpLifetime).Unix(),
	}); err != nil {
		return router.ServerError("failed to store challenge", err)
	}

	if err := channel.Send(e.Context(), sf.Destination, code); err != nil {
		// The challenge is unusable without its code; remove it so that the
		// subject's next login attempt starts from a clean slate.
		if _, derr := s.sessions.DeleteOTPChallenge(
			e.Context(),
			digest,
		); derr != nil {
			s.logger.ErrorContext(
				e.Context(),
				"Failed to delete undeliverable challenge",
				log.Err(derr),
			)
		}
		return router.ServerError("failed to deliver one-time password",
			err,
		)
	}

	return e.JSON(http.StatusOK, OTPChallengeResponse{
		Challenge: challenge,
		Channel:   sf.Channel,
		ExpiresIn: int64(s.otpLifetime.Seconds()),
	})
}

// VerifyOTP confirms a pending two-factor login with the one-time password
// delivered to the resource owner, and establishes the session on success.
//
// It expects an [OTPVerificationRequest] carrying the challenge handle
// returned by [Server.Login] and the code received over the side channel.
// Challenges are single-use: after a successful confirmation, or once the
// configured attempt limit is exhausted, the challenge is deleted and the
// client must restart the login.
//
// One-time passwords are short enough to be guessed, so the endpoint is
// deliberately hostile to guessing: failed attempts are counted against
// both the challenge and the throttle, and the code comparison runs in
// constant time.
func (s *Server) VerifyOTP(e *router.Exchange) error {
	if len(s.otpChannels) == 0 {
		e.Status(http.StatusNotFound)
		return nil
	}

	var req OTPVerificationRequest
	if err := e.BindJSON(&req); err != nil {
		return err
	}

	// Guesses are counted per challenge: an attacker holding one challenge
	// cannot spread guesses across it and a fresh allowance, and a
	// legitimate subject on a shared address is not locked out by someone
	// else's failures.
	digest := NewDigest(req.Challenge)
	otpKey := scopeOTP + string(digest)
	if s.throttled(e, otpKey) {
		return &router.Error{
			Status:      http.StatusTooManyRequests,
			Reason:      router.ReasonRateLimit,
			Description: "too many failed attempts; try again later",
		}
	}

	ch, err := s.sessions.GetOTPChallenge(e.Context(), digest)
	if err != nil {
		return router.ServerError("failed to retrieve challenge", err)
	}

	// The rejection is deliberately uniform: it does not reveal whether the
	// challenge never existed, expired, or was burned by too many attempts.
	invalid := &router.Error{
		Status:      http.StatusUnauthorized,
		Reason:      auth.ReasonAuthenticationFailed,
		Description: "invalid or expired challenge",
	}

	if ch.Challenge == "" ||
		(ch.ExpiresAt != 0 && s.clock().Unix() > ch.ExpiresAt) {
		s.penalize(otpKey, s.addr(e))
		return invalid
	}

	if ch.Attempts >= s.otpMaxAttempts {
		// The challenge is burned. Delete it best-effort; expiry cleans up
		// after a failed deletion.
		if _, err := s.sessions.DeleteOTPChallenge(
			e.Context(),
			digest,
		); err != nil {
			s.logger.ErrorContext(
				e.Context(),
				"Failed to delete burned challenge",
				log.Err(err),
			)
		}
		s.penalize(otpKey, s.addr(e))
		return invalid
	}

	// Record the attempt before comparing, so that a crash between compare
	// and update cannot hand out free guesses.
	ch.Attempts++
	if err := s.sessions.UpdateOTPChallenge(e.Context(), ch); err != nil {
		return router.ServerError("failed to update challenge", err)
	}

	if subtle.ConstantTimeCompare(
		[]byte(NewDigest(req.Code)),
		[]byte(ch.Code),
	) == 0 {
		s.penalize(otpKey, s.addr(e))
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "invalid code",
		}
	}

	// The atomic delete enforces single use: of two concurrent requests
	// carrying the correct code, only the one that performed the deletion
	// may establish a session.
	deleted, err := s.sessions.DeleteOTPChallenge(e.Context(), digest)
	if err != nil {
		return router.ServerError("failed to delete challenge", err)
	}
	if !deleted {
		return invalid
	}

	// The code is proven; drop any penalty from earlier attempts.
	s.clear(otpKey)

	sub, err := s.subjects.GetSubject(e.Context(), ch.SubjectID)
	if err != nil {
		return router.ServerError("failed to lookup subject", err)
	}
	if sub == nil {
		// The subject vanished between password verification and code
		// confirmation (e.g., account deletion).
		return invalid
	}

	if err := s.establishSession(e, sub); err != nil {
		return err
	}

	e.NoContent()

	return nil
}

// ResendOTP redelivers the one-time password for a pending two-factor
// login.
//
// It expects an [OTPResendRequest] carrying the challenge handle returned
// by [Server.Login]. A fresh code replaces the previous one, but the
// challenge itself — its handle, expiry, and attempt count — remains
// unchanged, so resending cannot be used to keep a login pending forever or
// to reset the guess budget. The number of resends per challenge is capped
// by [Config.OTPMaxResends], because every delivery costs money
// and unsolicited deliveries spam the subject.
func (s *Server) ResendOTP(e *router.Exchange) error {
	if len(s.otpChannels) == 0 {
		e.Status(http.StatusNotFound)
		return nil
	}

	var req OTPResendRequest
	if err := e.BindJSON(&req); err != nil {
		return err
	}

	digest := NewDigest(req.Challenge)
	otpKey := scopeOTP + string(digest)
	if s.throttled(e, otpKey) {
		return &router.Error{
			Status:      http.StatusTooManyRequests,
			Reason:      router.ReasonRateLimit,
			Description: "too many failed attempts; try again later",
		}
	}

	ch, err := s.sessions.GetOTPChallenge(e.Context(), digest)
	if err != nil {
		return router.ServerError("failed to retrieve challenge", err)
	}

	invalid := &router.Error{
		Status:      http.StatusUnauthorized,
		Reason:      auth.ReasonAuthenticationFailed,
		Description: "invalid or expired challenge",
	}

	if ch.Challenge == "" ||
		(ch.ExpiresAt != 0 && s.clock().Unix() > ch.ExpiresAt) {
		s.penalize(otpKey, s.addr(e))
		return invalid
	}

	if s.otpMaxResends < 0 || ch.Resends >= s.otpMaxResends {
		return &router.Error{
			Status:      http.StatusTooManyRequests,
			Reason:      router.ReasonRateLimit,
			Description: "resend limit reached",
		}
	}

	// The enrollment is re-read on every resend so that a change of phone
	// number or channel mid-login takes effect immediately.
	sf, err := s.subjects.GetSecondFactor(e.Context(), ch.SubjectID)
	if err != nil {
		return router.ServerError("failed to lookup second factor", err)
	}
	if sf == nil {
		// Enrollment was revoked mid-login; the pending challenge can never
		// be completed.
		if _, err := s.sessions.DeleteOTPChallenge(
			e.Context(),
			digest,
		); err != nil {
			s.logger.ErrorContext(
				e.Context(),
				"Failed to delete orphaned challenge",
				log.Err(err),
			)
		}
		return invalid
	}

	channel := s.otpChannels[sf.Channel]
	if channel == nil {
		return router.ServerError("second factor channel is not available",
			fmt.Errorf("no delivery channel configured for %q", sf.Channel),
		)
	}

	code, err := s.generateOTPCode(e.Context())
	if err != nil {
		return router.ServerError("failed to generate one-time password",
			err,
		)
	}

	// The fresh code invalidates the previous one before it leaves the
	// server: once the update is stored, only the latest delivery can
	// confirm the login.
	ch.Code = NewDigest(code)
	ch.Resends++
	if err := s.sessions.UpdateOTPChallenge(e.Context(), ch); err != nil {
		return router.ServerError("failed to update challenge", err)
	}

	if err := channel.Send(e.Context(), sf.Destination, code); err != nil {
		return router.ServerError("failed to deliver one-time password",
			err,
		)
	}

	return e.JSON(http.StatusOK, OTPChallengeResponse{
		Challenge: req.Challenge,
		Channel:   sf.Channel,
		ExpiresIn: max(ch.ExpiresAt-s.clock().Unix(), 0),
	})
}
