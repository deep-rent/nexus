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

// Package sms provides abstractions for sending SMS messages via Twilio.
//
// It defines a generic payload model ([Message]) and a common [Sender]
// interface for SMS delivery, decoupling business logic from the underlying
// mechanism.
//
// # Usage
//
// Create messages with [NewMessage] and dispatch them through your concrete
// [Sender] implementation.
//
//	msg := sms.NewMessage(
//		"+15558675309",
//		"+15551234567",
//		"Your verification code is 123456.",
//	)
//
//	sender := sms.NewSender(
//	  "twilio_sid",
//	  "twilio_auth_token",
//	)
//	err := sender.Send(ctx, msg)
package sms
