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

// Package mail provides abstractions for sending transactional emails.
//
// It defines a generic payload model ([Message]) and a common [Sender]
// interface for email delivery. This decouples the application's
// business logic from the underlying mechanism. By default, this package
// provides a production-ready Twilio SendGrid implementation initialized via
// [NewSender].
//
// # Usage
//
// Typically, you initialize a [Sender] at application startup, construct
// a [Message] using the fluent API, and pass it to the sender.
//
// Example:
//
//	// 1. Initialize the default SendGrid sender with a custom User-Agent.
//	sender := mail.NewSender("your-api-key",
//	  mail.WithUserAgent("MyApp/1.0"))
//
//	// 2. Construct the email message.
//	msg := mail.NewMessage(
//	  mail.New("no-reply@example.com", "My App"),
//	  "template-id-123",
//	  mail.NewRecipient(mail.New("user@example.com", "Alice")).
//	    AddTemplateData("name", "Alice"),
//	)
//
//	// 3. Dispatch the email.
//	err = sender.Send(context.Background(), msg)
package mail
