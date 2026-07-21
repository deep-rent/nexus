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

// Package apns provides an Apple Push Notification service (APNs) provider.
//
// It implements the [push.Sender] interface for delivering remote
// notifications to Apple devices using HTTP/2 and JWT authentication.
//
// # Usage
//
// Create a sender by providing your ES256 key ID, Apple team ID, and the
// PEM-encoded PKCS#8 private key contents.
//
//	sender := apns.New(
//		apns.Credentials{
//			KeyID:      "4F92S8D7W1",
//			TeamID:     "8M349Z7F2A",
//			PrivateKey: key, // PEM format
//		},
//		apns.WithBaseURL(apns.SandboxBaseURL),
//	)
//	err := sender.Send(ctx, msg)
package apns
