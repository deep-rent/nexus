package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestVerifier(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		wantErr error
	}{
		{"valid min length", MinVerifierLength, nil},
		{"valid mid length", 80, nil},
		{"valid max length", MaxVerifierLength, nil},
		{"invalid too short", MinVerifierLength - 1, ErrInvalidLength},
		{"invalid too long", MaxVerifierLength + 1, ErrInvalidLength},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verifier(tt.length)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Verifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if len(got) != tt.length {
				t.Errorf("Verifier() length = %d, want %d", len(got), tt.length)
			}
			if !isValidVerifier(got) {
				t.Errorf("Verifier() contains invalid characters: %q", got)
			}
		})
	}
}

func TestChallenge(t *testing.T) {
	validVerifier := strings.Repeat("a", MinVerifierLength)
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
			method:   MethodS256,
			want:     "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			wantErr:  nil,
		},
		{
			name:     "valid plain",
			verifier: validVerifier,
			method:   MethodPlain,
			want:     validVerifier,
			wantErr:  nil,
		},
		{
			name:     "invalid method",
			verifier: validVerifier,
			method:   "invalid",
			want:     "",
			wantErr:  ErrUnsupportedMethod,
		},
		{
			name:     "invalid characters",
			verifier: invalidVerifier,
			method:   MethodS256,
			want:     "",
			wantErr:  ErrInvalidVerifier,
		},
		{
			name:     "invalid length too short",
			verifier: "too-short",
			method:   MethodS256,
			want:     "",
			wantErr:  ErrInvalidLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Challenge(tt.verifier, tt.method)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Challenge() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if got != tt.want {
				t.Errorf("Challenge() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVerify(t *testing.T) {
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
		{"valid s256 match", v, c, MethodS256, true},
		{"valid plain match", v, v, MethodPlain, true},
		{"mismatch s256", v, "invalid-challenge", MethodS256, false},
		{"mismatch plain", v, "invalid-challenge", MethodPlain, false},
		{"empty verifier", "", c, MethodS256, false},
		{"empty challenge", v, "", MethodS256, false},
		{"invalid verifier characters", v + "!", c, MethodS256, false},
		{"invalid method", v, c, "invalid-method", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Verify(tt.verifier, tt.challenge, tt.method); got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	v, _ := Verifier(128)
	c, _ := Challenge(v, MethodS256)

	for b.Loop() {
		Verify(v, c, MethodS256)
	}
}

func BenchmarkVerifier(b *testing.B) {
	for b.Loop() {
		_, _ = Verifier(128)
	}
}
