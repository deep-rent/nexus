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

// Package nonce generates high-entropy random tokens and strings backed by the
// system's cryptographically secure random number generator.
//
// # Abstractions
//
// Randomness flows from a [Source], the single injection point of the package.
// Production code relies on [DefaultSource] (backed by [crypto/rand]); tests
// and specialized deployments substitute their own reader. Two generators build
// on a Source:
//
//   - [Generator] emits opaque, fixed-length byte tokens, optionally encoded as
//     base64url. Use it for bearer tokens, session IDs, and similar secrets.
//   - [Sampler] emits fixed-length strings over a custom alphabet using
//     unbiased rejection sampling. Use it for human-readable PINs and
//     verification codes.
//
// Both are configured once and are safe for concurrent use. Every draw takes a
// [context.Context], so cancellation propagates to sources that honor it.
//
// # Usage
//
// Generate an opaque 256-bit bearer token (43 base64url characters):
//
//	gen := nonce.NewGenerator(nil, 32)
//	tok, err := gen.Draw(ctx)
//
// The package-level [DefaultGenerator] serves the same 32-byte default:
//
//	tok, err := nonce.DefaultGenerator.Draw(ctx)
//
// Generate a 6-digit numeric verification PIN:
//
//	pin := nonce.NewSampler(nil, "0123456789", 6)
//	code, err := pin.Draw(ctx)
//
// Inject a custom [Source] to make generation deterministic under test:
//
//	gen := nonce.NewGenerator(fakeSource, 32)
package nonce
