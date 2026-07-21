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

// Package fcm provides a Firebase Cloud Messaging (FCM) v1 provider.
//
// It implements the [push.Sender] interface for delivering remote
// notifications to Android devices using OAuth 2.0 authentication.
//
// # Usage
//
// Create a sender by providing the contents of your Google Service Account
// JSON credentials file.
//
//	sender := fcm.New(
//		fcm.Credentials{
//			ProjectID:   "my-project",
//			ClientEmail: "test@my-project.iam.gserviceaccount.com",
//			PrivateKey:  string(key), // PEM data
//		},
//	)
//	err := sender.Send(ctx, msg)
package fcm
