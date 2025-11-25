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
		x5t string
		src string
	}{
		{
			"EdDSA",
			"q3TlIAMpJF6VoTuJuaLZDUzXbFV-k7kLhAi5gYmV37Y",
			"6fdfc2b56f326d45f47cdddd0a7c6a378ad92241d3183e2479be28604aa4f7a7",
			"Ed448.json",
		},
		{
			"EdDSA",
			"P6rOVdsYhY_b0VzNdk568I9tYrAnBw-WGgsMZ2zMOvA",
			"381004f8c7897d5ab2198c9cc2ab81a831f5d0827472a728c0e991e0b44da189",
			"Ed25519.json",
		},
		{
			"ES256",
			"chs_bZZOVng98tfs-pQRig3RTaXszdcZ0WsoyWORzDQ",
			"8ae7b0b40e5abe8670d6c50500625957e824a6aad1ffc60c7cd5a082bf02cdba",
			"ES256.json",
		},
		{
			"ES384",
			"HCgaZlHgiGkHQ9f3Q2FWYs_NtZzQsLWaii8puMRbhhE",
			"155477264a68dd6aa13969ccbbaa88c93511ccc779b9119441059298c2eb2b27",
			"ES384.json",
		},
		{
			"ES512",
			"3xQ6MwN6aFYouSGZyqv9DYvst-CV_12M58EvjJ6wHQs",
			"036a6650cb354e6227e38bb10cecc56a4958cec5f30417cb7d8b44e5cede1dd5",
			"ES512.json",
		},
		{
			"PS256",
			"1iPDx07kLtDB6MeYwD451j-NUaZFv3QS4mFCCdIbaeQ",
			"0ddbbcbf7bf93b579e2bbb550ebb44400789c64dbceff20b603bfdf2688f152a",
			"PS256.json",
		},
		{
			"PS384",
			"5q0HzRnzOR2DivWMl4q2MpKXy8IdnfYMxc-c1s6Olhc",
			"a371ace0a34d95b88f0cade1607149aa9fadcc3abf942717b36c04f7c00bc124",
			"PS384.json",
		},
		{
			"PS512",
			"6f-mwTH8QRxXXZHP7teEem1uqkGFYGPKSDxOqXc3xzQ",
			"262e6fb460d5d124953cdb83b836025e351d18255add4e0c03ca9c0643e38319",
			"PS512.json",
		},
		{
			"RS256",
			"KO4ZegrzU_W1RcC89v05Ev3C2JXHC2aQKNo08ZSbnC4",
			"72b885d85336f6b4ef73b1df7125ef8f416e63a00d6167aeb2dcaac3e2ce1446",
			"RS256.json",
		},
		{
			"RS384",
			"g1jIq7AVMQRV3YHbLk3tJfHUJfwgVuzPzkMK3R1K_GU",
			"ecd720239f966c6ef8e5212be757302e67b6435def75bed346bbdb183f623d29",
			"RS384.json",
		},
		{
			"RS512",
			"DYHSGgm9DBjiFYkciaL3lFjKDPJQc0BO6nS7IacanVU",
			"f23401b9e029adf752b1ea06b8e02020fb26fe96bf2f885d9c7f00c5ba5ce67e",
			"RS512.json",
		},
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
