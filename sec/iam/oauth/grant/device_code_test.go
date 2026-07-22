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

package grant

import (
	"net/url"
	"testing"
	"time"

	"uuid"

	"github.com/deep-rent/nexus/sec/iam/oauth"
)

func TestDeviceCodeGrant(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)
	clientID := uuid.New()
	subjectID := uuid.New()

	client := &fakeClient{id: clientID}

	code := func(status oauth.DeviceCodeStatus) oauth.DeviceCode {
		return oauth.DeviceCode{
			DeviceCode: newDigest("device-1"),
			UserCode:   newDigest("BCDF-GHJK"),
			ClientID:   clientID,
			SubjectID:  subjectID,
			Scope:      "read",
			Status:     status,
			ExpiresAt:  now.Add(10 * time.Minute).Unix(),
			Interval:   5,
		}
	}

	form := url.Values{"device_code": {"device-1"}}

	tests := []struct {
		name       string
		code       oauth.DeviceCode
		seed       bool
		data       url.Values
		wantCode   string
		wantDelete bool
	}{
		{
			name:     "missing device code",
			seed:     true,
			code:     code(oauth.DeviceCodeStatusPending),
			data:     url.Values{},
			wantCode: oauth.ErrorCodeInvalidRequest,
		},
		{
			name:     "unknown device code",
			seed:     false,
			data:     form,
			wantCode: oauth.ErrorCodeInvalidGrant,
		},
		{
			name: "client mismatch",
			seed: true,
			code: func() oauth.DeviceCode {
				c := code(oauth.DeviceCodeStatusPending)
				c.ClientID = uuid.New()
				return c
			}(),
			data:     form,
			wantCode: oauth.ErrorCodeInvalidGrant,
		},
		{
			name: "expired code",
			seed: true,
			code: func() oauth.DeviceCode {
				c := code(oauth.DeviceCodeStatusPending)
				c.ExpiresAt = now.Add(-time.Minute).Unix()
				return c
			}(),
			data:       form,
			wantCode:   oauth.ErrorCodeExpiredToken,
			wantDelete: true,
		},
		{
			name:     "pending",
			seed:     true,
			code:     code(oauth.DeviceCodeStatusPending),
			data:     form,
			wantCode: oauth.ErrorCodeAuthorizationPending,
		},
		{
			name: "polling too fast",
			seed: true,
			code: func() oauth.DeviceCode {
				c := code(oauth.DeviceCodeStatusPending)
				c.LastPolledAt = now.Add(-2 * time.Second).Unix()
				return c
			}(),
			data:     form,
			wantCode: oauth.ErrorCodeSlowDown,
		},
		{
			name:       "denied",
			seed:       true,
			code:       code(oauth.DeviceCodeStatusDenied),
			data:       form,
			wantCode:   oauth.ErrorCodeAccessDenied,
			wantDelete: true,
		},
		{
			name: "illegal status",
			seed: true,
			code: func() oauth.DeviceCode {
				c := code(oauth.DeviceCodeStatusPending)
				c.Status = "garbage"
				return c
			}(),
			data:     form,
			wantCode: oauth.ErrorCodeServerError,
		},
		{
			name:       "authorized",
			seed:       true,
			code:       code(oauth.DeviceCodeStatusAuthorized),
			data:       form,
			wantDelete: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newFakeTokens()
			if tt.seed {
				seed(t, store.deviceCodes, tt.code)
			}

			pro := newProposal(client, store, tt.data, now)
			iss, err := DeviceCode().Authorize(t.Context(), pro)

			if tt.wantDelete {
				if _, found, _ := store.deviceCodes.Get(
					t.Context(),
					newDigest("device-1"),
				); found {
					t.Error("device code should have been deleted")
				}
			}

			if tt.wantCode != "" {
				if got := errCode(err); got != tt.wantCode {
					t.Fatalf(
						"got error code %q; want %q (err: %v)",
						got,
						tt.wantCode,
						err,
					)
				}
				return
			}

			if err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}
			if iss.Subject != subjectID {
				t.Errorf("got subject %v; want %v", iss.Subject, subjectID)
			}
			if got, want := iss.Scope, "read"; got != want {
				t.Errorf("got scope %q; want %q", got, want)
			}
			if !iss.Refreshable {
				t.Error("issuance should be refreshable")
			}
		})
	}

	t.Run("pending poll records timestamp", func(t *testing.T) {
		t.Parallel()

		store := newFakeTokens()
		seed(t, store.deviceCodes, code(oauth.DeviceCodeStatusPending))

		pro := newProposal(client, store, form, now)
		_, err := DeviceCode().Authorize(t.Context(), pro)
		if got := errCode(err); got != oauth.ErrorCodeAuthorizationPending {
			t.Fatalf(
				"got error code %q; want %q",
				got,
				oauth.ErrorCodeAuthorizationPending,
			)
		}

		dc, _, _ := store.deviceCodes.Get(t.Context(), newDigest("device-1"))
		if got := dc.LastPolledAt; got != now.Unix() {
			t.Errorf("got last polled at %d; want %d", got, now.Unix())
		}

		// An immediate second poll must be throttled.
		pro = newProposal(client, store, form, now.Add(2*time.Second))
		_, err = DeviceCode().Authorize(t.Context(), pro)
		if got := errCode(err); got != oauth.ErrorCodeSlowDown {
			t.Fatalf("got error code %q; want %q", got, oauth.ErrorCodeSlowDown)
		}

		// After the interval has elapsed, polling resumes normally.
		pro = newProposal(client, store, form, now.Add(6*time.Second))
		_, err = DeviceCode().Authorize(t.Context(), pro)
		if got := errCode(err); got != oauth.ErrorCodeAuthorizationPending {
			t.Fatalf(
				"got error code %q; want %q",
				got,
				oauth.ErrorCodeAuthorizationPending,
			)
		}
	})
}
