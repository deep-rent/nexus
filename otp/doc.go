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

// Package otp implements generation and delivery of numeric one-time
// passwords (OTPs), as used for two-factor authentication and similar
// verification flows.
//
// The package deliberately covers only the two concerns that are independent
// of any particular authentication protocol: drawing a uniformly random
// numeric code ([Generate]) and delivering it to the user over a side
// channel ([Channel]). Storage, expiry, attempt counting, and rate limiting
// are policy decisions that belong to the consumer; the oauth package wires
// them into its login flow.
//
// # Delivery channels
//
// Two [Channel] adapters are provided out of the box: [SMS] delivers
// codes as text messages through an [sms.Sender], and [Mail]
// delivers them as transactional emails through a [mail.Sender]. Both
// adapters are thin: they format the code into the channel's payload shape
// and delegate dispatching entirely to the wrapped sender.
//
// # Usage
//
//	code, err := otp.Generate(6) // e.g., "042917"
//	if err != nil { ... }
//
//	channel := otp.SMS(
//	  sms.NewSender("twilio_sid", "twilio_auth_token"),
//	  "+15551234567", // from
//	  "",             // use DefaultSMSFormat
//	)
//	err = channel.Send(ctx, "+15558675309", code)
//
// # Security
//
// Codes returned by [Generate] are drawn from crypto/rand with rejection
// sampling, so every code of a given length is equally likely. Note that a
// short numeric code carries little entropy by design (a 6-digit code has
// only one million possible values): it is guessable by brute force unless
// the verifying side enforces a short lifetime, a strict attempt limit, and
// rate limiting. Never rely on the code alone.
package otp
