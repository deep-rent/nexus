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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"uuid"

	"github.com/deep-rent/nexus/net/router"
	"github.com/deep-rent/nexus/sec/auth"
	"github.com/deep-rent/nexus/sec/iam/flow"
	"github.com/deep-rent/nexus/sec/iam/internal/limit"
	"github.com/deep-rent/nexus/sec/iam/trust"
	"github.com/deep-rent/nexus/sys/log"
)

// Login authenticates a resource owner and either establishes a session or
// begins a multi-step login.
//
// It expects a JSON payload with username, password, and an optional remember
// flag. When no [Planner] is configured (see [WithFlow]), a verified password
// establishes the session directly and the endpoint responds 204.
//
// With a planner, a verified password is only the first factor. The server
// consults the planner for the remaining steps on this subject and device; if
// any remain, it responds 200 with a [FlowResponse] carrying a flow handle, and
// the client completes the login via [Server.Continue]. Clients therefore must
// distinguish a 204 (session established) from a 200 (further steps pending)
// response.
//
// Note: When calling this endpoint from a cross-origin frontend (e.g., an SPA),
// the CORS middleware must be configured with AllowCredentials set to true,
// and AllowOrigin must not be a wildcard ("*").
func (s *Server) Login(e *router.Exchange) error {
	var cred LoginRequest
	if err := e.BindJSON(&cred); err != nil {
		return err
	}

	// Guesses are counted per account, folded to lower case so that varying
	// the capitalization cannot buy a fresh allowance.
	userKey := limit.ScopeUser + strings.ToLower(cred.Username)
	if s.throttled(e, userKey) {
		return &router.Error{
			Status:      http.StatusTooManyRequests,
			Reason:      router.ReasonRateLimit,
			Description: "too many failed attempts; try again later",
		}
	}

	sub, err := s.subjects.Authenticate(
		e.Context(),
		cred.Username,
		cred.Password,
	)
	if err != nil {
		return router.ServerError("failed to lookup subject", err)
	}
	if sub == nil {
		s.penalize(userKey, s.addr(e))
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      router.ReasonValidationFailed,
			Description: "invalid credentials",
		}
	}

	// The password is proven; drop any penalty from earlier attempts.
	s.clear(userKey)

	// Without a planner, the password alone establishes the session.
	if s.flow == nil {
		return s.completeLogin(e, sub, cred.Remember)
	}

	// The password is the first factor; the planner decides the rest for this
	// subject and device.
	dev, err := s.deviceTrust(e.Context(), s.readTrustCookie(e), sub.ID())
	if err != nil {
		return router.ServerError("failed to evaluate device trust", err)
	}
	steps, err := s.planner(e.Context(), sub, dev, Steps{s})
	if err != nil {
		return router.ServerError("failed to plan login", err)
	}

	handle, res, err := s.flow.Begin(
		e.Context(), sub.ID().String(), cred.Remember, steps,
	)
	if err != nil {
		return router.ServerError("failed to begin login", err)
	}

	// No further steps: complete immediately (e.g. a trusted device).
	if res.Done() {
		return s.completeLogin(e, sub, res.Remember)
	}
	return e.JSON(http.StatusOK, FlowResponse{
		Handle: handle,
		Step:   res.Prompt.Step,
		Prompt: res.Prompt.Payload,
	})
}

// Identify starts a passwordless login: it identifies the subject by username
// and hands off to the login flow's factors to authenticate them.
//
// It expects an [IdentifyRequest] with a username. When the subject exists and
// the planner yields at least one factor, it responds 200 with a
// [FlowResponse]; the client then satisfies the factors via [Server.Continue]
// exactly as after a password login. Unlike the password login, it ignores any
// device trust — a passwordless login always walks its full factor chain — and
// it refuses to complete when the planner yields no factor, so a username alone
// can never establish a session.
//
// Every call is rate limited per username and address, because a successful
// call delivers a code (an email or SMS) and so has a cost. The endpoint is
// username-keyed and distinguishes a known from an unknown username by its
// response; a deployment that must not reveal which usernames exist should
// front it with an additional control such as a CAPTCHA or a strict global
// limit.
func (s *Server) Identify(e *router.Exchange) error {
	if s.flow == nil || !s.passwordless {
		e.Status(http.StatusNotFound)
		return nil
	}

	var req IdentifyRequest
	if err := e.BindJSON(&req); err != nil {
		return err
	}

	userKey := limit.ScopeUser + strings.ToLower(req.Username)
	if s.throttled(e, userKey) {
		return &router.Error{
			Status:      http.StatusTooManyRequests,
			Reason:      router.ReasonRateLimit,
			Description: "too many attempts; try again later",
		}
	}
	// Each identify triggers a factor delivery, so charge the throttle on every
	// call — success included — to bound code-send spam per username and
	// address.
	s.penalize(userKey, s.addr(e))

	sub, err := s.subjects.GetSubjectByUsername(e.Context(), req.Username)
	if err != nil {
		return router.ServerError("failed to lookup subject", err)
	}
	if sub == nil {
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      router.ReasonValidationFailed,
			Description: "invalid credentials",
		}
	}

	// Passwordless login ignores device trust: the flow must fully
	// authenticate, so the planner runs against an untrusted device.
	steps, err := s.planner(e.Context(), sub, trust.Device{}, Steps{s})
	if err != nil {
		return router.ServerError("failed to plan login", err)
	}
	if len(steps) == 0 {
		// A passwordless login with no factor would authenticate on a username
		// alone; refuse rather than establish a session.
		return router.ServerError("passwordless login has no factor",
			fmt.Errorf("planner yielded no steps for %s", sub.ID()),
		)
	}

	handle, res, err := s.flow.Begin(
		e.Context(), sub.ID().String(), req.Remember, steps,
	)
	if err != nil {
		return router.ServerError("failed to begin login", err)
	}
	// steps is non-empty, so the flow prompts rather than completing.
	return e.JSON(http.StatusOK, FlowResponse{
		Handle: handle,
		Step:   res.Prompt.Step,
		Prompt: res.Prompt.Payload,
	})
}

// Continue satisfies the active step of a pending multi-step login and advances
// it, establishing the session once every step is complete.
//
// It expects a [ContinueRequest] with the flow handle from [Server.Login] and
// the credential for the active step. On completion it responds 204 with a
// session cookie; while steps remain it responds 200 with the next
// [FlowResponse]. The planner is re-run each call, so a change to the subject's
// factors takes effect mid-login.
func (s *Server) Continue(e *router.Exchange) error {
	if s.flow == nil {
		e.Status(http.StatusNotFound)
		return nil
	}

	var req ContinueRequest
	if err := e.BindJSON(&req); err != nil {
		return err
	}

	flowKey := limit.ScopeOTP + string(s.digest(req.Handle))
	if s.throttled(e, flowKey) {
		return &router.Error{
			Status:      http.StatusTooManyRequests,
			Reason:      router.ReasonRateLimit,
			Description: "too many failed attempts; try again later",
		}
	}

	res, err := s.flow.Continue(
		e.Context(),
		req.Handle,
		s.plan(s.readTrustCookie(e)),
		flow.Input{Value: req.Code, Raw: []byte(req.Credential)},
	)
	if err != nil {
		return router.ServerError("failed to continue login", err)
	}
	return s.afterStep(e, flowKey, req.Handle, res)
}

// Action drives an out-of-band operation on the active step of a pending login,
// such as resending a one-time password or switching the delivery channel.
//
// It expects an [ActionRequest] with the flow handle and the action. It
// responds 200 with a refreshed [FlowResponse] on success, 429 when a per-step
// limit is reached, and 400 for an unsupported action or channel.
func (s *Server) Action(e *router.Exchange) error {
	if s.flow == nil {
		e.Status(http.StatusNotFound)
		return nil
	}

	var req ActionRequest
	if err := e.BindJSON(&req); err != nil {
		return err
	}

	flowKey := limit.ScopeOTP + string(s.digest(req.Handle))
	if s.throttled(e, flowKey) {
		return &router.Error{
			Status:      http.StatusTooManyRequests,
			Reason:      router.ReasonRateLimit,
			Description: "too many failed attempts; try again later",
		}
	}

	res, err := s.flow.Act(
		e.Context(),
		req.Handle,
		s.plan(s.readTrustCookie(e)),
		flow.Action{Name: req.Action, Extra: map[string]string{
			"channel": req.Channel,
		}},
	)
	if err != nil {
		switch {
		case errors.Is(err, flow.ErrRateLimited):
			return &router.Error{
				Status:      http.StatusTooManyRequests,
				Reason:      router.ReasonRateLimit,
				Description: "resend limit reached",
			}
		case errors.Is(err, flow.ErrRejected):
			return &router.Error{
				Status:      http.StatusBadRequest,
				Reason:      router.ReasonValidationFailed,
				Description: "the action could not be performed",
			}
		default:
			return router.ServerError("failed to run login action", err)
		}
	}
	return s.afterStep(e, flowKey, req.Handle, res)
}

// plan builds a [flow.Plan] that resolves the subject recorded in the
// transaction and re-runs the planner, folding in the requesting device's trust
// (from the trust token) so plan changes take effect mid-login.
func (s *Server) plan(trustToken string) flow.Plan {
	return func(ctx context.Context, owner string) ([]flow.Step, error) {
		id, err := uuid.Parse(owner)
		if err != nil {
			return nil, err
		}
		sub, err := s.subjects.GetSubject(ctx, id)
		if err != nil {
			return nil, err
		}
		if sub == nil {
			return nil, fmt.Errorf("subject %s no longer exists", id)
		}
		dev, err := s.deviceTrust(ctx, trustToken, id)
		if err != nil {
			return nil, err
		}
		return s.planner(ctx, sub, dev, Steps{s})
	}
}

// afterStep maps a step outcome onto the HTTP response, establishing the
// session on completion and applying throttle penalties to failures.
func (s *Server) afterStep(
	e *router.Exchange,
	flowKey, handle string,
	res flow.Result,
) error {
	switch res.Status {
	case flow.StatusDone:
		// Every step is proven; drop any penalty from earlier attempts.
		s.clear(flowKey)
		id, err := uuid.Parse(res.Owner)
		if err != nil {
			return router.ServerError("invalid flow owner", err)
		}
		sub, err := s.subjects.GetSubject(e.Context(), id)
		if err != nil {
			return router.ServerError("failed to lookup subject", err)
		}
		if sub == nil {
			return invalidLogin()
		}
		return s.completeLogin(e, sub, res.Remember)
	case flow.StatusPrompt:
		return e.JSON(http.StatusOK, FlowResponse{
			Handle: handle,
			Step:   res.Prompt.Step,
			Prompt: res.Prompt.Payload,
		})
	case flow.StatusWrongInput:
		s.penalize(flowKey, s.addr(e))
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "invalid code",
		}
	default:
		s.penalize(flowKey, s.addr(e))
		return invalidLogin()
	}
}

// invalidLogin is the uniform rejection for an absent, expired, or aborted
// login flow. It does not reveal which applies.
func invalidLogin() error {
	return &router.Error{
		Status:      http.StatusUnauthorized,
		Reason:      auth.ReasonAuthenticationFailed,
		Description: "invalid or expired login",
	}
}

// completeLogin establishes the session and, for a remembered login on a
// flow-enabled server, issues a device trust token so later logins may skip
// factors. A failure to persist the trust never fails the login.
func (s *Server) completeLogin(
	e *router.Exchange,
	sub Subject,
	remember bool,
) error {
	if err := s.session(e, sub, remember); err != nil {
		return err
	}
	if remember && s.flow != nil {
		token, err := s.issueTrustedDevice(e.Context(), sub.ID(), e.R.UserAgent())
		if err != nil {
			s.logger.ErrorContext(e.Context(),
				"Failed to issue device trust", log.Err(err),
			)
		} else {
			e.SetCookie(s.newTrustCookie(
				token, int(s.trustedDeviceLifetime.Seconds()),
			))
		}
	}
	e.NoContent()
	return nil
}

// readTrustCookie returns the remember-me device trust token from the request,
// or the empty string when absent.
func (s *Server) readTrustCookie(e *router.Exchange) string {
	if c, err := e.Cookie(s.trustCookieName); err == nil {
		return c.Value
	}
	return ""
}

// session establishes a session through the session engine and sets the
// session cookie on the user-agent. It is shared by the password login and
// external login flows.
//
// A remembered session is set as a persistent cookie lasting
// [Config.RememberedSessionLifetime]; otherwise it is a browser-session cookie
// that lapses when the user-agent closes, with the server-side record bounded
// by [Config.SessionLifetime].
func (s *Server) session(e *router.Exchange, sub Subject, remember bool) error {
	lifetime := s.sessionLifetime
	maxAge := 0
	if remember {
		lifetime = s.rememberedSessionLifetime
		maxAge = int(lifetime.Seconds())
	}

	key, err := s.sessions.Establish(e.Context(), sub.ID().String(), lifetime)
	if err != nil {
		return router.ServerError("failed to establish session", err)
	}

	e.SetCookie(s.newSessionCookie(key, maxAge))

	return nil
}

// Logout terminates the resource owner's session.
//
// It identifies the session via the session cookie, deletes the mapping from
// the [SubjectStore], and clears the cookie on the user-agent by setting a
// negative Max-Age value.
func (s *Server) Logout(e *router.Exchange) error {
	cookie, err := e.Cookie(s.sessionCookieName)
	if err == nil && cookie.Value != "" {
		if _, err := s.sessions.Destroy(
			e.Context(),
			cookie.Value,
		); err != nil {
			s.logger.ErrorContext(
				e.Context(),
				"Failed to destroy session",
				log.Err(err),
			)
		}
	}

	// Instruct the browser to wipe all local state (cookies, storage, cache).
	// Note: The double-quotes around the asterisk are required by the spec.
	e.SetHeader("Clear-Site-Data", `"*"`)

	e.SetCookie(s.newSessionCookie("", -1))

	e.NoContent()

	return nil
}

// ExternalLogin initiates a social authentication flow by redirecting the
// resource owner to the requested external identity provider.
func (s *Server) ExternalLogin(e *router.Exchange) error {
	name := e.R.PathValue("provider")
	idp, ok := s.idps[name]
	if !ok {
		e.Status(http.StatusNotFound)
		return nil
	}

	state, err := s.nonce.Draw(e.Context())
	if err != nil {
		return router.ServerError("failed to generate state", err)
	}

	e.SetCookie(s.newStateCookie(state, 300))

	authURL, err := idp.AuthURL(e.Context(), state)
	if err != nil {
		return router.ServerError(
			"failed to initiate external login",
			err,
		)
	}

	return e.Redirect(authURL, http.StatusFound)
}

// ExternalCallback handles the redirect from an external identity provider,
// verifies the state, exchanges credentials for an external identity, and
// establishes a local session.
//
// If a protocol or server error occurs during the exchange, the user-agent
// is redirected back to the configured login portal with the error details
// appended as query parameters.
func (s *Server) ExternalCallback(e *router.Exchange) error {
	err := s.externalCallback(e)
	if v, ok := errors.AsType[*router.Error](err); ok {
		u, err := url.Parse(s.loginTerminalURI)
		if err != nil {
			return router.ServerError(
				"failed to parse login terminal URI",
				err,
			)
		}
		q := u.Query()
		q.Set("error_status", strconv.Itoa(v.Status))
		q.Set("error_reason", v.Reason)
		q.Set("error_description", v.Description)
		if v.ID != "" {
			q.Set("error_id", v.ID)
		}
		u.RawQuery = q.Encode()

		// The user-agent sits in a top-level navigation here, so the error
		// must be delivered as an actual redirect back to the login portal.
		return e.Redirect(u.String(), http.StatusFound)
	}

	return err
}

func (s *Server) externalCallback(e *router.Exchange) error {
	name := e.R.PathValue("provider")
	idp, ok := s.idps[name]
	if !ok {
		return &router.Error{
			Status:      http.StatusNotFound,
			Reason:      router.ReasonNotFound,
			Description: "unknown identity provider",
		}
	}

	cookie, err := e.Cookie(s.stateCookieName)
	if err != nil || cookie.Value == "" {
		return &router.Error{
			Status:      http.StatusBadRequest,
			Reason:      router.ReasonValidationFailed,
			Description: "missing or expired state cookie",
		}
	}

	// Clear the state cookie immediately to prevent replay attacks.
	e.SetCookie(s.newStateCookie("", -1))

	// FormValue transparently covers both query-mode (GET) and form_post
	// (POST) callback responses.
	state := e.R.FormValue("state")
	if state != cookie.Value {
		return &router.Error{
			Status:      http.StatusBadRequest,
			Reason:      router.ReasonValidationFailed,
			Description: "state mismatch",
		}
	}

	identity, err := idp.Exchange(e.Context(), e.R)
	if err != nil {
		id := router.ErrorID()

		s.logger.ErrorContext(
			e.Context(),
			"Failed to process external exchange",
			slog.String("idp", name),
			slog.String("error_id", id),
			log.Err(err),
		)

		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "failed to exchange external credentials",
			ID:          id,
		}
	}

	sub, err := s.subjects.GetSubjectByExternalID(
		e.Context(),
		name,
		identity,
	)
	if err != nil {
		return router.ServerError("failed to lookup subject", err)
	}
	if sub == nil {
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "external identity is not linked to any local subject",
		}
	}

	if err := s.session(e, sub, false); err != nil {
		return err
	}

	return e.Redirect(s.loginRedirectURI, http.StatusFound)
}
