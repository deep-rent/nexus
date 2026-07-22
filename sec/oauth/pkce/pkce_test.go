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

package pkce_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/sec/oauth/pkce"
)

func TestVerifier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		length  int
		wantErr error
	}{
		{"valid min length", pkce.MinVerifierLength, nil},
		{"valid mid length", 80, nil},
		{"valid max length", pkce.MaxVerifierLength, nil},
		{
			"invalid too short",
			pkce.MinVerifierLength - 1,
			pkce.ErrInvalidLength,
		},
		{"invalid too long", pkce.MaxVerifierLength + 1, pkce.ErrInvalidLength},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := pkce.Verifier(t.Context(), tt.length)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error: got %v; want %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if len(got) != tt.length {
				t.Errorf("got length %d; want %d", len(got), tt.length)
			}
			if !pkce.IsUnreserved(got) {
				t.Errorf("should not contain reserved characters: %q", got)
			}
		})
	}
}

func TestChallenge(t *testing.T) {
	t.Parallel()
	validVerifier := strings.Repeat("a", pkce.MinVerifierLength)
	invalidVerifier := validVerifier + "!"

	tests := []struct {
		name     string
		verifier string
		method   string
		want     string
		wantErr  error
	}{
		{
			name:     "valid s256",
			verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			method:   pkce.MethodS256,
			want:     "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			wantErr:  nil,
		},
		{
			name:     "valid plain",
			verifier: validVerifier,
			method:   pkce.MethodPlain,
			want:     validVerifier,
			wantErr:  nil,
		},
		{
			name:     "invalid method",
			verifier: validVerifier,
			method:   "invalid",
			want:     "",
			wantErr:  pkce.ErrUnsupportedMethod,
		},
		{
			name:     "invalid characters",
			verifier: invalidVerifier,
			method:   pkce.MethodS256,
			want:     "",
			wantErr:  pkce.ErrInvalidVerifier,
		},
		{
			name:     "invalid length too short",
			verifier: "too-short",
			method:   pkce.MethodS256,
			want:     "",
			wantErr:  pkce.ErrInvalidLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := pkce.Challenge(tt.verifier, tt.method)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error: got %v; want %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()
	v := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(v))
	c := base64.RawURLEncoding.EncodeToString(sum[:])

	tests := []struct {
		name      string
		verifier  string
		challenge string
		method    string
		want      bool
	}{
		{"valid s256 match", v, c, pkce.MethodS256, true},
		{"valid plain match", v, v, pkce.MethodPlain, true},
		{"mismatch s256", v, "invalid-challenge", pkce.MethodS256, false},
		{"mismatch plain", v, "invalid-challenge", pkce.MethodPlain, false},
		{"empty verifier", "", c, pkce.MethodS256, false},
		{"empty challenge", v, "", pkce.MethodS256, false},
		{"invalid verifier characters", v + "!", c, pkce.MethodS256, false},
		{"invalid method", v, c, "invalid-method", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := pkce.Verify(
				tt.verifier, tt.challenge, tt.method,
			); got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	v, _ := pkce.Verifier(b.Context(), 128)
	c, _ := pkce.Challenge(v, pkce.MethodS256)

	for b.Loop() {
		pkce.Verify(v, c, pkce.MethodS256)
	}
}

func BenchmarkVerifier(b *testing.B) {
	for b.Loop() {
		_, _ = pkce.Verifier(b.Context(), 128)
	}
}

func TestIsUnreserved(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		give string
		want bool
	}{
		{"all unreserved characters", pkce.Alphabet, true},
		{"contains invalid character", "abcd!123", false},
		{"empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := pkce.IsUnreserved(tt.give); got != tt.want {
				t.Errorf("for %q: got %v; want %v", tt.give, got, tt.want)
			}
		})
	}
}

func TestSupports(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method string
		want   bool
	}{
		{"S256 supported", pkce.MethodS256, true},
		{"plain supported", pkce.MethodPlain, true},
		{"unsupported method", "S512", false},
		{"empty method", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := pkce.Supports(tt.method); got != tt.want {
				t.Errorf(
					"for method %q: got %v; want %v", tt.method, got, tt.want,
				)
			}
		})
	}
}
