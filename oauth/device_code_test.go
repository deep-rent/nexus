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
	"net/url"
	"testing"
	"time"

	"uuid"
)

func TestDeviceCodeGrant(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)
	clientID := uuid.New()
	subjectID := uuid.New()

	client := &fakeClient{id: clientID}

	code := func(status DeviceCodeStatus) DeviceCode {
		return DeviceCode{
			DeviceCode: "device-1",
			UserCode:   "BCDF-GHJK",
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
		code       DeviceCode
		seed       bool
		data       url.Values
		wantCode   string
		wantDelete bool
	}{
		{
			name:     "missing device code",
			seed:     true,
			code:     code(DeviceCodeStatusPending),
			data:     url.Values{},
			wantCode: ErrorCodeInvalidRequest,
		},
		{
			name:     "unknown device code",
			seed:     false,
			data:     form,
			wantCode: ErrorCodeInvalidGrant,
		},
		{
			name: "client mismatch",
			seed: true,
			code: func() DeviceCode {
				c := code(DeviceCodeStatusPending)
				c.ClientID = uuid.New()
				return c
			}(),
			data:     form,
			wantCode: ErrorCodeInvalidGrant,
		},
		{
			name: "expired code",
			seed: true,
			code: func() DeviceCode {
				c := code(DeviceCodeStatusPending)
				c.ExpiresAt = now.Add(-time.Minute).Unix()
				return c
			}(),
			data:       form,
			wantCode:   ErrorCodeExpiredToken,
			wantDelete: true,
		},
		{
			name:     "pending",
			seed:     true,
			code:     code(DeviceCodeStatusPending),
			data:     form,
			wantCode: ErrorCodeAuthorizationPending,
		},
		{
			name: "polling too fast",
			seed: true,
			code: func() DeviceCode {
				c := code(DeviceCodeStatusPending)
				c.LastPolledAt = now.Add(-2 * time.Second).Unix()
				return c
			}(),
			data:     form,
			wantCode: ErrorCodeSlowDown,
		},
		{
			name:       "denied",
			seed:       true,
			code:       code(DeviceCodeStatusDenied),
			data:       form,
			wantCode:   ErrorCodeAccessDenied,
			wantDelete: true,
		},
		{
			name: "illegal status",
			seed: true,
			code: func() DeviceCode {
				c := code(DeviceCodeStatusPending)
				c.Status = "garbage"
				return c
			}(),
			data:     form,
			wantCode: ErrorCodeServerError,
		},
		{
			name:       "authorized",
			seed:       true,
			code:       code(DeviceCodeStatusAuthorized),
			data:       form,
			wantDelete: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newFakeSessionStore()
			if tt.seed {
				store.deviceCodes[tt.code.DeviceCode] = tt.code
			}

			pro := newProposal(client, store, tt.data, now)
			iss, err := DeviceCodeGrant().Authorize(t.Context(), pro)

			if tt.wantDelete {
				if _, ok := store.deviceCodes["device-1"]; ok {
					t.Error("device code should have been deleted")
				}
			}

			if tt.wantCode != "" {
				if got := errCode(err); got != tt.wantCode {
					t.Fatalf("got error code %q; want %q (err: %v)", got, tt.wantCode, err)
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

		store := newFakeSessionStore()
		store.deviceCodes["device-1"] = code(DeviceCodeStatusPending)

		pro := newProposal(client, store, form, now)
		_, err := DeviceCodeGrant().Authorize(t.Context(), pro)
		if got := errCode(err); got != ErrorCodeAuthorizationPending {
			t.Fatalf("got error code %q; want %q", got, ErrorCodeAuthorizationPending)
		}

		if got := store.deviceCodes["device-1"].LastPolledAt; got != now.Unix() {
			t.Errorf("got last polled at %d; want %d", got, now.Unix())
		}

		// An immediate second poll must be throttled.
		pro = newProposal(client, store, form, now.Add(2*time.Second))
		_, err = DeviceCodeGrant().Authorize(t.Context(), pro)
		if got := errCode(err); got != ErrorCodeSlowDown {
			t.Fatalf("got error code %q; want %q", got, ErrorCodeSlowDown)
		}

		// After the interval has elapsed, polling resumes normally.
		pro = newProposal(client, store, form, now.Add(6*time.Second))
		_, err = DeviceCodeGrant().Authorize(t.Context(), pro)
		if got := errCode(err); got != ErrorCodeAuthorizationPending {
			t.Fatalf("got error code %q; want %q", got, ErrorCodeAuthorizationPending)
		}
	})
}
