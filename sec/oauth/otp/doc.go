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

// Package otp generates, delivers, and verifies numeric one-time passwords, as
// used for two-factor authentication and for confirming ownership of a channel
// such as an email address or phone number.
//
// # The engine
//
// A [Challenger] runs the full challenge lifecycle over a [Store]: [Begin]
// mints a challenge and delivers a code, [Verify] confirms a submitted code,
// and [Resend] rotates and redelivers it. The engine is transport-agnostic —
// it neither speaks HTTP nor throttles — so it can back an oauth two-factor
// login or a standalone verification flow equally. It records only digests, and
// its verification is deliberately hostile to guessing: attempts are counted
// before the constant-time comparison, and a correct code deletes the challenge
// atomically to enforce single use. Logical results are reported as an
// [Outcome]; Go errors are reserved for storage and delivery failures. The
// [Challenge.Purpose] field namespaces distinct flows so a handle minted for
// one cannot complete another.
//
// # Delivery
//
// The code is delivered by a [Method], which pairs a stable ID with a
// [Deliverer] closure. Because the caller builds the Deliverer knowing the
// recipient, it owns every destination, template, and locale choice; the engine
// stays oblivious. [ViaText], [ViaMail], and [ViaPush] construct Deliverers over
// the notify senders (SMS/WhatsApp, email, and push respectively). A subject may
// be offered several Methods, letting a client pick a channel and switch it on
// resend.
//
// # Usage
//
//	ch := otp.New(store, otp.WithLifetime(5*time.Minute))
//
//	method := otp.Method{
//		ID:      "sms",
//		Deliver: otp.ViaText(sender, "+15551234567", "+15558675309", ""),
//	}
//	handle, _, err := ch.Begin(ctx, "verify:phone", userID, method)
//	// ... hand the handle to the client; the code arrives over the channel ...
//	out, err := ch.Verify(ctx, "verify:phone", handle, submittedCode)
//	if err == nil && out.OK() {
//		// out.Owner == userID: ownership confirmed.
//	}
//
// # Security
//
// Codes from [Generate] are sampled uniformly from a [nonce.Sampler], so every
// code of a given length is equally likely. A short numeric code carries
// little entropy by design (a 6-digit code has one million values): it is
// guessable by brute force unless the verifier enforces a short lifetime, a
// strict attempt limit, and rate limiting. The [Challenger] enforces the first
// two; supply the rate limiting around it. Never rely on the code alone.
package otp
