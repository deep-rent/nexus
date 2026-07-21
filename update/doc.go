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

// Package update provides functionality to check for newer GitHub releases.
//
// This package queries the GitHub Releases API to retrieve the latest
// release and compares its tag against the current application version using
// semantic versioning.
//
// # Usage
//
// Initialize a [Config] and use the [Check] function to look for new versions.
//
// Example:
//
//	cfg := &update.Config{
//	  Owner:      "deep-rent",
//	  Repository: "vouch",
//	  Current:    "v1.0.0",
//	  UserAgent:  "Vouch/1.0.0",
//	}
//
//	// Check for updates.
//	rel, err := update.Check(context.Background(), cfg)
//	if err != nil {
//	  log.Printf("Failed to check for updates: %v", err)
//	} else if rel != nil {
//	  log.Printf("New version available: %s (see %s)", rel.Version, rel.URL)
//	}
package update
