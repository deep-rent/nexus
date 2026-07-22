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

package nonce_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/sec/nonce"
)

// mockErrSource is a [nonce.Source] that always fails with a fixed error.
type mockErrSource struct{ err error }

func (s mockErrSource) Read(context.Context, []byte) error { return s.err }

// mockSeqSource is a deterministic [nonce.Source] that fills buffers from a
// repeating byte sequence, letting tests pin down exactly which bytes the
// samplers observe. It is not safe for concurrent use.
type mockSeqSource struct {
	data []byte
	pos  int
}

func (s *mockSeqSource) Read(_ context.Context, b []byte) error {
	for i := range b {
		b[i] = s.data[s.pos%len(s.data)]
		s.pos++
	}
	return nil
}

// mockSource returns the buffers produced by fill on successive calls,
// counting how many reads occurred. It exercises the refill loop.
type mockSource struct {
	fill  func(call int, b []byte)
	calls int
}

func (s *mockSource) Read(_ context.Context, b []byte) error {
	s.calls++
	s.fill(s.calls, b)
	return nil
}

func TestDefaultSource(t *testing.T) {
	t.Parallel()

	b := make([]byte, 16)
	if err := nonce.DefaultSource.Read(t.Context(), b); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := nonce.DefaultSource.Read(ctx, b); !errors.Is(err,
		context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestNewGeneratorPanics(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("expected panic, got none")
				}
			}()
			nonce.NewGenerator(nil, n)
		}()
	}
}

func TestGeneratorBytes(t *testing.T) {
	t.Parallel()

	gen := nonce.NewGenerator(nil, 16)

	b, err := gen.Bytes(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp, act := 16, len(b); exp != act {
		t.Fatalf("expected %d bytes, got %d", exp, act)
	}
}

func TestGeneratorDraw(t *testing.T) {
	t.Parallel()

	gen := nonce.NewGenerator(nil, 32)

	tok1, err := gen.Draw(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 32 bytes encode to 43 unpadded base64url characters.
	if exp, act := 43, len(tok1); exp != act {
		t.Fatalf("expected %d chars for 32 bytes, got %d (%s)", exp, act, tok1)
	}
	// base64url uses only [A-Za-z0-9-_] and carries no padding.
	const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, c := range tok1 {
		if !strings.ContainsRune(allowed, c) {
			t.Fatalf("unexpected character %q in token %q", c, tok1)
		}
	}

	tok2, err := gen.Draw(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok1 == tok2 {
		t.Fatalf("expected unique tokens, got identical: %s", tok1)
	}
}

func TestGeneratorSourceError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("boom")
	gen := nonce.NewGenerator(mockErrSource{sentinel}, 16)

	if _, err := gen.Bytes(t.Context()); !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel from Bytes, got %v", err)
	}
	if _, err := gen.Draw(t.Context()); !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel from Draw, got %v", err)
	}
}

func TestDefaultGenerator(t *testing.T) {
	t.Parallel()

	tok, err := nonce.DefaultGenerator.Draw(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp, act := 43, len(tok); exp != act {
		t.Fatalf("expected 32-byte default token (%d chars), got %d", exp, act)
	}
}

func TestNewSamplerPanics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		alphabet string
		n        int
	}{
		{"nonpositive size", "0123456789", 0},
		{"negative size", "0123456789", -3},
		{"alphabet too small", strings.Repeat("A", nonce.MinAlphabetSize-1), 4},
		{"alphabet too large", strings.Repeat("A", nonce.MaxAlphabetSize+1), 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Fatal("expected panic, got none")
				}
			}()
			nonce.NewSampler(nil, tt.alphabet, tt.n)
		})
	}
}

func TestSamplerDraw(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		alphabet string
		n        int
	}{
		{"numeric pin", "0123456789", 6},
		{"hex", "0123456789abcdef", 32},
		{"binary alphabet", "AB", 64},
		{"multibyte runes", "αβγδεζ", 12},
		{"single draw", "XYZ", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := nonce.NewSampler(nil, tt.alphabet, tt.n)
			out, err := s.Draw(t.Context())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// Count runes, not bytes, so multibyte alphabets are handled.
			if exp, act := tt.n, len([]rune(out)); exp != act {
				t.Fatalf("expected %d runes, got %d (%q)", exp, act, out)
			}
			for _, c := range out {
				if !strings.ContainsRune(tt.alphabet, c) {
					t.Fatalf("rune %q not in alphabet %q", c, tt.alphabet)
				}
			}
		})
	}
}

// TestSamplerUnbiased feeds a known byte sequence and asserts the exact
// mapping, verifying both the modulo mapping and that out-of-range bytes are
// rejected.
func TestSamplerUnbiased(t *testing.T) {
	t.Parallel()

	// N = 3, so lim = 256 - (256 % 3) = 255; the byte 255 must be rejected.
	const alphabet = "ABC"
	src := &mockSeqSource{data: []byte{255, 0, 1, 2, 3}}
	s := nonce.NewSampler(src, alphabet, 4)

	out, err := s.Draw(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 255 rejected; 0->A, 1->B, 2->C, 3%3=0->A.
	if exp := "ABCA"; out != exp {
		t.Fatalf("expected %q, got %q", exp, out)
	}
}

// TestSamplerRefill forces the scratch buffer to be exhausted before the string
// is complete, exercising the read-again loop.
func TestSamplerRefill(t *testing.T) {
	t.Parallel()

	// N = 3, lim = 255. The first read yields only rejected bytes, so Draw must
	// read a second time to make progress.
	src := &mockSource{fill: func(call int, b []byte) {
		if call == 1 {
			for i := range b {
				b[i] = 255 // all rejected
			}
			return
		}
		for i := range b {
			b[i] = byte(i % 3) // 0,1,2 -> A,B,C
		}
	}}
	s := nonce.NewSampler(src, "ABC", 3)

	out, err := s.Draw(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp := "ABC"; out != exp {
		t.Fatalf("expected %q, got %q", exp, out)
	}
	if src.calls != 2 {
		t.Fatalf("expected 2 reads (one wasted on rejects), got %d", src.calls)
	}
}

func TestSamplerSourceError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("boom")
	s := nonce.NewSampler(mockErrSource{sentinel}, "0123456789", 6)

	if _, err := s.Draw(t.Context()); !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
}

func TestSamplerContextCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	s := nonce.NewSampler(nil, "0123456789", 6)
	if _, err := s.Draw(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestSamplerCoverage checks that, over a large sample, every symbol of the
// alphabet is produced — a coarse guard against a mapping that silently drops
// symbols. The odds of a symbol never appearing across this many draws are
// vanishingly small.
func TestSamplerCoverage(t *testing.T) {
	t.Parallel()

	const alphabet = "0123456789"
	s := nonce.NewSampler(nil, alphabet, 1000)

	out, err := s.Draw(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, c := range alphabet {
		if !strings.ContainsRune(out, c) {
			t.Fatalf("symbol %q never sampled across %d draws", c, len(out))
		}
	}
}
