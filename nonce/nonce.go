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

package nonce

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

const (
	// MinAlphabetSize is the minimum number of unique characters required in a
	// custom alphabet passed to [NewSampler].
	MinAlphabetSize = 2

	// MaxAlphabetSize is the maximum number of unique characters allowed in a
	// custom alphabet passed to [NewSampler]. The bound is 256 because sampling
	// draws one byte per candidate rune, and a single byte cannot address more
	// than 256 symbols without bias.
	MaxAlphabetSize = 256
)

// Source supplies cryptographically secure random bytes. It is the injection
// point of the package: production code uses [DefaultSource], while tests or
// specialized deployments can substitute a deterministic reader, a hardware
// module, or a remote KMS.
//
// Implementations must fill buffers completely, honor cancellation via the
// input context, and be safe for concurrent use.
type Source interface {
	// Read fills the byte buffer entirely with random bytes, or returns an
	// error. Note that a partial read must be reported as an error rather than
	// a short fill.
	Read(ctx context.Context, b []byte) error
}

// source is the default [Source], backed by [crypto/rand].
type source struct{}

func (source) Read(ctx context.Context, b []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := io.ReadFull(rand.Reader, b)
	return err
}

// DefaultSource draws entropy from [crypto/rand], the operating system's
// cryptographically secure random number generator. It is used whenever a
// constructor receives a nil [Source].
var DefaultSource Source = source{}

// Generator produces fixed-length, high-entropy tokens by drawing raw bytes
// from a [Source]. It is safe for concurrent use.
//
// Use a Generator for opaque, machine-readable secrets such as bearer tokens,
// session identifiers, or CSRF tokens, where the full byte range is desirable.
// For human-readable output constrained to a specific alphabet, use a
// [Sampler] instead.
type Generator struct {
	src Source
	n   int
}

// NewGenerator returns a [Generator] that draws n bytes per token from the
// the given source. If the source is nil, [DefaultSource] is used.
//
// A token of n bytes carries 8n bits of entropy; 32 bytes (256 bits) is a
// sound default for unguessable secrets. NewGenerator panics if n is not
// positive, since the size is configuration rather than runtime input.
func NewGenerator(src Source, n int) *Generator {
	if n <= 0 {
		panic("size must be positive")
	}
	if src == nil {
		src = DefaultSource
	}
	return &Generator{src: src, n: n}
}

// Bytes returns n freshly drawn random bytes, where n is the size fixed at
// construction. It returns any error reported by the underlying [Source],
// including cancellation of ctx.
func (g *Generator) Bytes(ctx context.Context) ([]byte, error) {
	b := make([]byte, g.n)
	if err := g.src.Read(ctx, b); err != nil {
		return nil, err
	}
	return b, nil
}

// Draw returns a token encoded as an unpadded base64url string. The output is
// safe for inclusion in URLs, HTTP headers, and JSON payloads; 32 bytes of
// entropy yield a 43-character string. It returns any error reported by the
// underlying [Source], including cancellation of ctx.
func (g *Generator) Draw(ctx context.Context) (string, error) {
	b, err := g.Bytes(ctx)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DefaultGenerator draws 32-byte (256-bit) tokens from [DefaultSource]. It is a
// ready-to-use replacement for one-off opaque token generation.
var DefaultGenerator = NewGenerator(nil, 32)

// Sampler produces fixed-length strings whose characters are drawn uniformly
// from a custom alphabet. It is safe for concurrent use.
//
// Sampling maps random bytes onto runes using rejection sampling, which
// discards the biased tail of the byte range so that every rune is equally
// likely. The alphabet is UTF-8 safe and may contain multi-byte runes, making
// a Sampler suitable for human-readable PINs, coupon codes, or short
// verification tokens.
type Sampler struct {
	src   Source
	runes []rune
	n     int
	lim   int // largest byte value + 1 that maps without modulo bias
	buf   int // scratch buffer size, over-provisioned for rejected bytes
}

// NewSampler returns a [Sampler] that draws n-rune strings from the given
// alphabet using the provided source. If the source is nil, [DefaultSource]
// is used.
//
// The alphabet's distinct runes define the output symbols. It panics if the
// size is not positive, or if the alphabet holds fewer than [MinAlphabetSize]
// or more than [MaxAlphabetSize] runes, since these are configuration rather
// than runtime input. Duplicate runes are not collapsed and will be sampled
// more frequently; supply a de-duplicated alphabet if uniform weighting
// matters.
func NewSampler(src Source, alphabet string, n int) *Sampler {
	if n <= 0 {
		panic("size must be positive")
	}
	runes := []rune(alphabet)
	N := len(runes)
	switch {
	case N < MinAlphabetSize:
		panic(fmt.Sprintf(
			"alphabet must contain %d characters or less",
			MinAlphabetSize,
		))
	case N > MaxAlphabetSize:
		panic(fmt.Sprintf(
			"alphabet must contain %d characters or more",
			MaxAlphabetSize,
		))
	}
	if src == nil {
		src = DefaultSource
	}

	// Reject byte values at or above lim so that the remaining values divide
	// evenly across the alphabet, eliminating modulo bias.
	lim := MaxAlphabetSize - (MaxAlphabetSize % N)

	// On average 256/lim bytes are consumed per accepted rune. Size the scratch
	// buffer to cover that expected cost plus a small margin, so a single read
	// usually suffices. Correctness never depends on this: Draw reads again
	// whenever the buffer is exhausted before n runes are filled.
	buf := (n*MaxAlphabetSize)/lim + 8

	return &Sampler{src: src, runes: runes, n: n, lim: lim, buf: buf}
}

// Draw returns a string of n runes drawn uniformly from the alphabet, where n
// is the size fixed at construction. It returns any error reported by the
// underlying [Source], including cancellation of the context.
func (s *Sampler) Draw(ctx context.Context) (string, error) {
	N := len(s.runes)
	out := make([]rune, s.n)
	b := make([]byte, s.buf)

	filled := 0
	for filled < s.n {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := s.src.Read(ctx, b); err != nil {
			return "", err
		}
		for _, w := range b {
			if int(w) < s.lim {
				out[filled] = s.runes[int(w)%N]
				filled++
				if filled == s.n {
					break
				}
			}
		}
	}
	return string(out), nil
}
