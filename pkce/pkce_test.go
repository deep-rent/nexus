package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestVerifier(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		wantErr error
	}{
		{"Valid Min Length", MinVerifierLength, nil},
		{"Valid Mid Length", 80, nil},
		{"Valid Max Length", MaxVerifierLength, nil},
		{"Invalid Too Short", MinVerifierLength - 1, ErrInvalidLength},
		{"Invalid Too Long", MaxVerifierLength + 1, ErrInvalidLength},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verifier(tt.length)
			if err != tt.wantErr {
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
		name      string
		verifier  string
		method    string
		want      string
		wantErr   error
	}{
		{
			name:     "Valid S256",
			verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			method:   MethodS256,
			want:     "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			wantErr:  nil,
		},
		{
			name:     "Valid Plain",
			verifier: validVerifier,
			method:   MethodPlain,
			want:     validVerifier,
			wantErr:  nil,
		},
		{
			name:     "Invalid Method",
			verifier: validVerifier,
			method:   "invalid",
			want:     "",
			wantErr:  ErrUnsupportedMethod,
		},
		{
			name:     "Invalid Characters",
			verifier: invalidVerifier,
			method:   MethodS256,
			want:     "",
			wantErr:  ErrInvalidVerifier,
		},
		{
			name:     "Invalid Length Too Short",
			verifier: "too-short",
			method:   MethodS256,
			want:     "",
			wantErr:  ErrInvalidLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Challenge(tt.verifier, tt.method)
			if err != tt.wantErr {
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
		{"Valid S256 Match", v, c, MethodS256, true},
		{"Valid Plain Match", v, v, MethodPlain, true},
		{"Mismatch S256", v, "invalid-challenge", MethodS256, false},
		{"Mismatch Plain", v, "invalid-challenge", MethodPlain, false},
		{"Empty Verifier", "", c, MethodS256, false},
		{"Empty Challenge", v, "", MethodS256, false},
		{"Invalid Verifier Characters", v + "!", c, MethodS256, false},
		{"Invalid Method", v, c, "invalid-method", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Verify(tt.verifier, tt.challenge, tt.method); got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}
