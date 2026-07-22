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

// Package push provides abstractions for sending mobile push notifications.
//
// It defines a generic payload model ([Message]) and a common [Sender]
// interface for delivery via APNs (Apple) or FCM (Firebase/Android).
//
// # Usage
//
// Create messages with [NewMessage], optionally attach custom key-value pairs
// via [Message.WithData], and dispatch them through your concrete [Sender]
// implementation.
//
//	msg := push.NewMessage(
//		"New Match!",
//		"Someone liked your profile.",
//		push.Target{Token: "device_token_here"},
//	).WithData(map[string]any{"match_id": 123})
//
//	err := sender.Send(ctx, msg)
package push
