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
	"testing"
	"time"

	"uuid"
)

func TestTrustedDevice_IssueAndTrust(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	token, err := env.server.issueTrustedDevice(
		t.Context(),
		env.subject.id,
		"iPhone",
	)
	if err != nil {
		t.Fatalf("issueTrustedDevice: %v", err)
	}
	if token == "" {
		t.Fatal("issueTrustedDevice returned an empty token")
	}

	dev, err := env.server.deviceTrust(t.Context(), token, env.subject.id)
	if err != nil {
		t.Fatalf("deviceTrust: %v", err)
	}
	if !dev.Trusted {
		t.Error("device should be trusted for the enrolling subject")
	}
}

func TestTrustedDevice_BoundToSubject(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	token, err := env.server.issueTrustedDevice(t.Context(), env.subject.id, "")
	if err != nil {
		t.Fatalf("issueTrustedDevice: %v", err)
	}

	// A token issued for one subject must not trust the device for another.
	dev, err := env.server.deviceTrust(t.Context(), token, uuid.New())
	if err != nil {
		t.Fatalf("deviceTrust: %v", err)
	}
	if dev.Trusted {
		t.Error("trust must be bound to the enrolling subject")
	}
}

func TestTrustedDevice_EmptyAndUnknown(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	for _, token := range []string{"", "not-a-real-token"} {
		dev, err := env.server.deviceTrust(t.Context(), token, env.subject.id)
		if err != nil {
			t.Fatalf("deviceTrust(%q): %v", token, err)
		}
		if dev.Trusted {
			t.Errorf("token %q should not be trusted", token)
		}
	}
}

func TestTrustedDevice_Expired(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	token, err := env.server.issueTrustedDevice(t.Context(), env.subject.id, "")
	if err != nil {
		t.Fatalf("issueTrustedDevice: %v", err)
	}

	env.now = env.now.Add(DefaultTrustedDeviceLifetime + time.Second)

	dev, err := env.server.deviceTrust(t.Context(), token, env.subject.id)
	if err != nil {
		t.Fatalf("deviceTrust: %v", err)
	}
	if dev.Trusted {
		t.Error("an expired trust token should not be trusted")
	}
}

func TestTrustedDevice_Revoke(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	token, err := env.server.issueTrustedDevice(t.Context(), env.subject.id, "")
	if err != nil {
		t.Fatalf("issueTrustedDevice: %v", err)
	}

	if err := env.server.trust.Revoke(t.Context(), token); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	dev, err := env.server.deviceTrust(t.Context(), token, env.subject.id)
	if err != nil {
		t.Fatalf("deviceTrust: %v", err)
	}
	if dev.Trusted {
		t.Error("a revoked device should not be trusted")
	}
}

func TestTrustedDevice_RevokeAllForSubject(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	t1, _ := env.server.issueTrustedDevice(t.Context(), env.subject.id, "phone")
	t2, _ := env.server.issueTrustedDevice(
		t.Context(),
		env.subject.id,
		"laptop",
	)

	if err := env.server.RevokeTrustedDevices(
		t.Context(),
		env.subject.id,
	); err != nil {
		t.Fatalf("RevokeTrustedDevices: %v", err)
	}

	for _, token := range []string{t1, t2} {
		dev, err := env.server.deviceTrust(t.Context(), token, env.subject.id)
		if err != nil {
			t.Fatalf("deviceTrust: %v", err)
		}
		if dev.Trusted {
			t.Error("all trusted devices should have been revoked")
		}
	}
}
