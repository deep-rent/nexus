package jwk_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		alg string
		kid string
		src string
	}{
		{"EdDSA", "q3TlIAMpJF6VoTuJuaLZDUzXbFV-k7kLhAi5gYmV37Y", "Ed448.json"},
		{"EdDSA", "P6rOVdsYhY_b0VzNdk568I9tYrAnBw-WGgsMZ2zMOvA", "Ed25519.json"},
		{"ES256", "chs_bZZOVng98tfs-pQRig3RTaXszdcZ0WsoyWORzDQ", "ES256.json"},
		{"ES384", "HCgaZlHgiGkHQ9f3Q2FWYs_NtZzQsLWaii8puMRbhhE", "ES384.json"},
		{"ES512", "3xQ6MwN6aFYouSGZyqv9DYvst-CV_12M58EvjJ6wHQs", "ES512.json"},
		{"PS256", "1iPDx07kLtDB6MeYwD451j-NUaZFv3QS4mFCCdIbaeQ", "PS256.json"},
		{"PS384", "5q0HzRnzOR2DivWMl4q2MpKXy8IdnfYMxc-c1s6Olhc", "PS384.json"},
		{"PS512", "6f-mwTH8QRxXXZHP7teEem1uqkGFYGPKSDxOqXc3xzQ", "PS512.json"},
		{"RS256", "KO4ZegrzU_W1RcC89v05Ev3C2JXHC2aQKNo08ZSbnC4", "RS256.json"},
		{"RS384", "g1jIq7AVMQRV3YHbLk3tJfHUJfwgVuzPzkMK3R1K_GU", "RS384.json"},
		{"RS512", "DYHSGgm9DBjiFYkciaL3lFjKDPJQc0BO6nS7IacanVU", "RS512.json"},
	}

	for _, tc := range tests {
		t.Run(tc.src, func(t *testing.T) {
			in := read(t, tc.src)
			key, err := jwk.Parse(in)
			require.NoError(t, err)
			require.Equal(t, tc.alg, key.Algorithm())
			require.Equal(t, tc.kid, key.KeyID())
		})
	}
}

func TestParseSet(t *testing.T) {
	in := read(t, "set.json")
	set, err := jwk.ParseSet(in)
	require.NoError(t, err)
	require.Equal(t, 11, set.Len())
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return b
}
