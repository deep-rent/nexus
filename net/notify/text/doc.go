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

// Package text provides abstractions for sending text messages via Twilio,
// over both SMS and WhatsApp.
//
// It defines a generic payload model ([Message]) and a common [Sender]
// interface, decoupling business logic from the underlying mechanism.
//
// # SMS and WhatsApp
//
// The channel is selected entirely by the address format of a message's To and
// From fields, matching Twilio's convention: a bare E.164 number (e.g.
// "+15558675309") is delivered as an SMS, while a number wrapped by [WhatsApp]
// (e.g. "whatsapp:+15558675309") is delivered over WhatsApp. The two ends of a
// message must use the same channel.
//
// # Usage
//
// Create messages with [NewMessage] and dispatch them through your concrete
// [Sender] implementation.
//
//	msg := text.NewMessage(
//		"+15558675309",
//		"+15551234567",
//		"Your verification code is 123456.",
//	)
//
//	sender := text.NewSender(
//	  "twilio_sid",
//	  "twilio_auth_token",
//	)
//	err := sender.Send(ctx, msg)
//
// The same sender delivers over WhatsApp when both numbers are wrapped:
//
//	msg := text.NewMessage(
//		text.WhatsApp("+15558675309"),
//		text.WhatsApp("+15551234567"),
//		"Your verification code is 123456.",
//	)
package text
