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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/deep-rent/nexus/otp"
	"github.com/deep-rent/nexus/throttle"
)

const (
	testPhone = "+15558675309"
	testEmail = "alice@example.com"
)

// fakeOTPSender is an in-memory [otp.Sender] that records deliveries.
type fakeOTPSender struct {
	to    []string
	codes []string
	err   error
}

func (s *fakeOTPSender) Send(_ context.Context, to, code string) error {
	if s.err != nil {
		return s.err
	}
	s.to = append(s.to, to)
	s.codes = append(s.codes, code)
	return nil
}

var _ otp.Sender = (*fakeOTPSender)(nil)

// otpEnv bundles a [testEnv] with the fakes backing its two-factor setup.
// The default subject is enrolled with the SMS channel.
type otpEnv struct {
	*testEnv
	sms  *fakeOTPSender
	mail *fakeOTPSender
}

// newOTPEnv builds a two-factor enabled environment. The given config is
// completed with fake senders and deterministic generators: challenges are
// numbered "challenge-1", "challenge-2", ... and codes "000001", "000002",
// and so on.
func newOTPEnv(
	t *testing.T,
	cfg SecondFactorConfig,
	opts ...Option,
) *otpEnv {
	t.Helper()

	sms := &fakeOTPSender{}
	mail := &fakeOTPSender{}
	cfg.SMS = sms
	cfg.Mail = mail

	var codes, challenges int
	opts = append([]Option{
		WithSecondFactor(cfg),
		WithOTPCodeGenerator(func(context.Context) (string, error) {
			codes++
			return fmt.Sprintf("%06d", codes), nil
		}),
		WithOTPChallengeGenerator(func(context.Context) (string, error) {
			challenges++
			return fmt.Sprintf("challenge-%d", challenges), nil
		}),
	}, opts...)

	env := &otpEnv{testEnv: newTestEnv(t, opts...), sms: sms, mail: mail}
	env.subjects.factors[env.subject.id] = &SecondFactor{
		Channel:     SecondFactorChannelSMS,
		Destination: testPhone,
	}
	return env
}

// beginLogin performs the password phase of a two-factor login and returns
// the challenge response.
func (env *otpEnv) beginLogin(t *testing.T) OTPChallengeResponse {
	t.Helper()
	w := postJSON(
		env.testEnv,
		PathLogin,
		`{"username":"alice","password":"wonderland"}`,
	)
	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
	}
	if sessionCookie(w) != nil {
		t.Fatal("no session cookie should be set before OTP confirmation")
	}
	return decodeJSON[OTPChallengeResponse](t, w)
}

// lastCode returns the most recently delivered code on the given sender.
func lastCode(t *testing.T, sender *fakeOTPSender) string {
	t.Helper()
	if len(sender.codes) == 0 {
		t.Fatal("no code was delivered")
	}
	return sender.codes[len(sender.codes)-1]
}

func TestLoginSecondFactor(t *testing.T) {
	t.Parallel()

	t.Run("returns challenge instead of session", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})

		res := env.beginLogin(t)

		if res.Challenge == "" {
			t.Fatal("missing challenge")
		}
		if res.Channel != SecondFactorChannelSMS {
			t.Errorf("got channel %q; want %q", res.Channel, "sms")
		}
		if want := int64(DefaultOTPLifetime.Seconds()); res.ExpiresIn != want {
			t.Errorf("got expires_in %d; want %d", res.ExpiresIn, want)
		}
		if len(env.subjects.sessions) != 0 {
			t.Error("no session should have been created")
		}

		if len(env.sms.to) != 1 || env.sms.to[0] != testPhone {
			t.Errorf("got deliveries %v; want one to %q", env.sms.to, testPhone)
		}

		ch, ok := env.sessions.otpChallenges[NewDigest(res.Challenge)]
		if !ok {
			t.Fatal("challenge was not stored")
		}
		if ch.SubjectID != env.subject.id {
			t.Errorf("got subject %v; want %v", ch.SubjectID, env.subject.id)
		}
		if ch.Code != NewDigest(lastCode(t, env.sms)) {
			t.Error("stored code digest does not match the delivered code")
		}
		want := env.now.Add(DefaultOTPLifetime).Unix()
		if ch.ExpiresAt != want {
			t.Errorf("got expiry %d; want %d", ch.ExpiresAt, want)
		}
	})

	t.Run("password alone suffices without enrollment", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})
		delete(env.subjects.factors, env.subject.id)

		w := postJSON(
			env.testEnv,
			PathLogin,
			`{"username":"alice","password":"wonderland"}`,
		)
		if w.Code != http.StatusNoContent {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusNoContent)
		}
		if sessionCookie(w) == nil {
			t.Error("missing session cookie")
		}
	})

	t.Run("delivers over the enrolled channel", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})
		env.subjects.factors[env.subject.id] = &SecondFactor{
			Channel:     SecondFactorChannelEmail,
			Destination: testEmail,
		}

		res := env.beginLogin(t)

		if res.Channel != SecondFactorChannelEmail {
			t.Errorf("got channel %q; want %q", res.Channel, "email")
		}
		if len(env.mail.to) != 1 || env.mail.to[0] != testEmail {
			t.Errorf(
				"got deliveries %v; want one to %q",
				env.mail.to,
				testEmail,
			)
		}
		if len(env.sms.to) != 0 {
			t.Error("no SMS should have been sent")
		}
	})

	t.Run("unconfigured channel fails closed", func(t *testing.T) {
		t.Parallel()
		// Only SMS is configured, but the subject enrolled email.
		env := newTestEnv(t, WithSecondFactor(SecondFactorConfig{
			SMS: &fakeOTPSender{},
		}))
		env.subjects.factors[env.subject.id] = &SecondFactor{
			Channel:     SecondFactorChannelEmail,
			Destination: testEmail,
		}

		w := postJSON(
			env,
			PathLogin,
			`{"username":"alice","password":"wonderland"}`,
		)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf(
				"got status %d; want %d",
				w.Code,
				http.StatusInternalServerError,
			)
		}
		if len(env.subjects.sessions) != 0 {
			t.Error("no session should have been created")
		}
	})

	t.Run("delivery failure removes the challenge", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})
		env.sms.err = errors.New("provider down")

		w := postJSON(
			env.testEnv,
			PathLogin,
			`{"username":"alice","password":"wonderland"}`,
		)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf(
				"got status %d; want %d",
				w.Code,
				http.StatusInternalServerError,
			)
		}
		if len(env.sessions.otpChallenges) != 0 {
			t.Error("undeliverable challenge should have been deleted")
		}
	})

	t.Run("default generator honors code length", func(t *testing.T) {
		t.Parallel()
		sender := &fakeOTPSender{}
		env := newTestEnv(t, WithSecondFactor(SecondFactorConfig{
			SMS:        sender,
			CodeLength: 8,
		}))
		env.subjects.factors[env.subject.id] = &SecondFactor{
			Channel:     SecondFactorChannelSMS,
			Destination: testPhone,
		}

		w := postJSON(
			env,
			PathLogin,
			`{"username":"alice","password":"wonderland"}`,
		)
		if w.Code != http.StatusOK {
			t.Fatalf(
				"got status %d; want %d: %s",
				w.Code,
				http.StatusOK,
				w.Body,
			)
		}

		code := lastCode(t, sender)
		if len(code) != 8 {
			t.Errorf("got code %q; want 8 digits", code)
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Errorf("got code %q; want digits only", code)
			}
		}
	})
}

func TestVerifyOTP(t *testing.T) {
	t.Parallel()

	verify := func(
		env *otpEnv,
		challenge, code string,
	) *httptest.ResponseRecorder {
		return postJSON(
			env.testEnv,
			PathLoginOTP,
			fmt.Sprintf(`{"challenge":%q,"code":%q}`, challenge, code),
		)
	}

	t.Run("confirms the login", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})
		res := env.beginLogin(t)

		w := verify(env, res.Challenge, lastCode(t, env.sms))
		if w.Code != http.StatusNoContent {
			t.Fatalf(
				"got status %d; want %d: %s",
				w.Code,
				http.StatusNoContent,
				w.Body,
			)
		}

		cookie := sessionCookie(w)
		if cookie == nil || cookie.Value == "" {
			t.Fatal("missing session cookie")
		}
		if got, ok := env.subjects.sessions[cookie.Value]; !ok {
			t.Error("session should have been persisted")
		} else if got != env.subject.id {
			t.Errorf("session maps to %v; want %v", got, env.subject.id)
		}
		if len(env.sessions.otpChallenges) != 0 {
			t.Error("challenge should have been deleted after confirmation")
		}
	})

	t.Run("rejects a wrong code but allows a retry", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})
		res := env.beginLogin(t)

		w := verify(env, res.Challenge, "999999")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}

		ch := env.sessions.otpChallenges[NewDigest(res.Challenge)]
		if ch.Attempts != 1 {
			t.Errorf("got %d attempts; want 1", ch.Attempts)
		}

		w = verify(env, res.Challenge, lastCode(t, env.sms))
		if w.Code != http.StatusNoContent {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusNoContent)
		}
	})

	t.Run("rejects an unknown challenge", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})

		w := verify(env, "no-such-challenge", "123456")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("rejects an expired challenge", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})
		res := env.beginLogin(t)

		env.now = env.now.Add(DefaultOTPLifetime + time.Second)

		w := verify(env, res.Challenge, lastCode(t, env.sms))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
		if len(env.subjects.sessions) != 0 {
			t.Error("no session should have been created")
		}
	})

	t.Run("burns the challenge after too many attempts", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{MaxAttempts: 2})
		res := env.beginLogin(t)

		for range 2 {
			if w := verify(
				env,
				res.Challenge,
				"999999",
			); w.Code != http.StatusUnauthorized {
				t.Fatalf(
					"got status %d; want %d",
					w.Code,
					http.StatusUnauthorized,
				)
			}
		}

		// Even the correct code is refused once the budget is exhausted.
		w := verify(env, res.Challenge, lastCode(t, env.sms))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
		if len(env.sessions.otpChallenges) != 0 {
			t.Error("burned challenge should have been deleted")
		}
	})

	t.Run("challenges are single use", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})
		res := env.beginLogin(t)
		code := lastCode(t, env.sms)

		if w := verify(
			env,
			res.Challenge,
			code,
		); w.Code != http.StatusNoContent {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusNoContent)
		}
		if w := verify(
			env,
			res.Challenge,
			code,
		); w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("rejects a vanished subject", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})
		res := env.beginLogin(t)
		delete(env.subjects.subjects, env.subject.id)

		w := verify(env, res.Challenge, lastCode(t, env.sms))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
		if len(env.subjects.sessions) != 0 {
			t.Error("no session should have been created")
		}
	})

	t.Run("validates the payload", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})

		w := postJSON(env.testEnv, PathLoginOTP, `{"challenge":"x"}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("endpoint is absent without second factor", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		w := postJSON(env, PathLoginOTP, `{"challenge":"x","code":"123456"}`)
		if w.Code != http.StatusNotFound {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusNotFound)
		}
	})
}

func TestResendOTP(t *testing.T) {
	t.Parallel()

	resend := func(env *otpEnv, challenge string) *httptest.ResponseRecorder {
		return postJSON(
			env.testEnv,
			PathLoginOTPResend,
			fmt.Sprintf(`{"challenge":%q}`, challenge),
		)
	}

	verify := func(
		env *otpEnv,
		challenge, code string,
	) *httptest.ResponseRecorder {
		return postJSON(
			env.testEnv,
			PathLoginOTP,
			fmt.Sprintf(`{"challenge":%q,"code":%q}`, challenge, code),
		)
	}

	t.Run("replaces the code", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})
		res := env.beginLogin(t)
		old := lastCode(t, env.sms)

		w := resend(env, res.Challenge)
		if w.Code != http.StatusOK {
			t.Fatalf(
				"got status %d; want %d: %s",
				w.Code,
				http.StatusOK,
				w.Body,
			)
		}

		re := decodeJSON[OTPChallengeResponse](t, w)
		if re.Challenge != res.Challenge {
			t.Errorf("got challenge %q; want %q", re.Challenge, res.Challenge)
		}
		if re.Channel != SecondFactorChannelSMS {
			t.Errorf("got channel %q; want %q", re.Channel, "sms")
		}

		fresh := lastCode(t, env.sms)
		if fresh == old {
			t.Fatal("resend should have delivered a fresh code")
		}
		if got := env.sessions.otpChallenges[NewDigest(res.Challenge)]; got.Resends != 1 {
			t.Errorf("got %d resends; want 1", got.Resends)
		}

		// The superseded code is dead; the fresh one confirms the login.
		if w := verify(
			env,
			res.Challenge,
			old,
		); w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
		if w := verify(
			env,
			res.Challenge,
			fresh,
		); w.Code != http.StatusNoContent {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusNoContent)
		}
	})

	t.Run("does not extend the expiry", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})
		res := env.beginLogin(t)

		env.now = env.now.Add(2 * time.Minute)

		w := resend(env, res.Challenge)
		if w.Code != http.StatusOK {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusOK)
		}

		re := decodeJSON[OTPChallengeResponse](t, w)
		want := int64((DefaultOTPLifetime - 2*time.Minute).Seconds())
		if re.ExpiresIn != want {
			t.Errorf("got expires_in %d; want %d", re.ExpiresIn, want)
		}
	})

	t.Run("enforces the resend limit", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{MaxResends: 1})
		res := env.beginLogin(t)

		if w := resend(env, res.Challenge); w.Code != http.StatusOK {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusOK)
		}
		if w := resend(
			env,
			res.Challenge,
		); w.Code != http.StatusTooManyRequests {
			t.Fatalf(
				"got status %d; want %d",
				w.Code,
				http.StatusTooManyRequests,
			)
		}
	})

	t.Run("negative limit disables resends", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{MaxResends: -1})
		res := env.beginLogin(t)

		if w := resend(
			env,
			res.Challenge,
		); w.Code != http.StatusTooManyRequests {
			t.Fatalf(
				"got status %d; want %d",
				w.Code,
				http.StatusTooManyRequests,
			)
		}
	})

	t.Run("rejects an unknown challenge", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})

		if w := resend(
			env,
			"no-such-challenge",
		); w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("rejects an expired challenge", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})
		res := env.beginLogin(t)

		env.now = env.now.Add(DefaultOTPLifetime + time.Second)

		if w := resend(env, res.Challenge); w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("revoked enrollment orphans the challenge", func(t *testing.T) {
		t.Parallel()
		env := newOTPEnv(t, SecondFactorConfig{})
		res := env.beginLogin(t)
		delete(env.subjects.factors, env.subject.id)

		w := resend(env, res.Challenge)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
		if len(env.sessions.otpChallenges) != 0 {
			t.Error("orphaned challenge should have been deleted")
		}
	})
}

func TestSecondFactorThrottle(t *testing.T) {
	t.Parallel()

	// The allowance tolerates exactly two failed attempts before locking
	// out, mirroring TestThrottleIntegration.
	newThrottled := func(t *testing.T, now *time.Time) *otpEnv {
		t.Helper()
		return newOTPEnv(t, SecondFactorConfig{},
			withThrottle(throttle.New(throttle.Config{
				Rate:  rate.Limit(1),
				Burst: 10,
				Clock: func() time.Time { return *now },
			})),
			withThrottlePenalty(5),
		)
	}

	t.Run("code guessing locks out per challenge", func(t *testing.T) {
		t.Parallel()
		now := time.Unix(1_752_000_000, 0)
		env := newThrottled(t, &now)
		res := env.beginLogin(t)

		guess := func(challenge string) int {
			w := postJSON(
				env.testEnv,
				PathLoginOTP,
				fmt.Sprintf(`{"challenge":%q,"code":"999999"}`, challenge),
			)
			return w.Code
		}

		for i := range 2 {
			if code := guess(res.Challenge); code != http.StatusUnauthorized {
				t.Fatalf(
					"attempt %d: got status %d; want %d",
					i,
					code,
					http.StatusUnauthorized,
				)
			}
		}

		if code := guess(res.Challenge); code != http.StatusTooManyRequests {
			t.Fatalf(
				"got status %d; want %d",
				code,
				http.StatusTooManyRequests,
			)
		}

		// The resend endpoint draws from the same bucket.
		w := postJSON(
			env.testEnv,
			PathLoginOTPResend,
			fmt.Sprintf(`{"challenge":%q}`, res.Challenge),
		)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf(
				"got status %d; want %d for a resend after lockout",
				w.Code,
				http.StatusTooManyRequests,
			)
		}

		// A different challenge is unaffected.
		other := env.beginLogin(t)
		if code := guess(other.Challenge); code != http.StatusUnauthorized {
			t.Errorf(
				"got status %d; want %d for a different challenge",
				code,
				http.StatusUnauthorized,
			)
		}
	})
}

func TestWithSecondFactorPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("WithSecondFactor without channels did not panic")
		}
	}()
	newTestEnv(t, WithSecondFactor(SecondFactorConfig{}))
}
