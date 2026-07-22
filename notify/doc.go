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

// Package notify groups the transactional delivery packages under a common
// namespace. It contains no code of its own; it exists to document the family
// and its shared shape.
//
// Each subpackage targets one medium through a single provider, but all follow
// the same design so they compose interchangeably:
//
//   - A provider-agnostic message type built with a NewMessage constructor and
//     validated by a Validate method.
//   - A Sender interface wrapping Send(ctx, msg), safe for concurrent use and
//     honoring context cancellation, with a concrete provider-backed sender
//     from NewSender.
//   - An APIError carrying the provider's status, unwrapping to a package-level
//     ErrDispatchFailed sentinel for use with errors.Is.
//
// # Subpackages
//
//   - [github.com/deep-rent/nexus/notify/mail]: transactional email via
//     SendGrid dynamic templates.
//   - [github.com/deep-rent/nexus/notify/text]: SMS and WhatsApp via Twilio.
//   - [github.com/deep-rent/nexus/notify/push]: push notifications, with
//     provider subpackages for APNs and FCM.
//
// Higher-level flows that deliver codes over these channels (such as one-time
// password challenges) live in [github.com/deep-rent/nexus/oauth/otp], which
// builds on the senders defined here.
package notify
