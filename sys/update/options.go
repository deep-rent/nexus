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

package update

import (
	"net/http"
)

// Default configuration values for the [Updater].
const (
	// DefaultBaseURL is the default GitHub API base URL.
	DefaultBaseURL = "https://api.github.com"
)

// Config holds the configuration for the [Updater].
type Config struct {
	// BaseURL is the base URL for the GitHub API. It defaults to
	// [DefaultBaseURL] if not set.
	BaseURL string
	// Owner is the GitHub repository owner (required).
	Owner string
	// Repo is the name of the GitHub repository (required).
	Repo string
	// Current is the current version string of the application (required).
	Current string
	// UserAgent is the value for the User-Agent header sent with requests.
	UserAgent string
	// Token is the GitHub Personal Access Token used for authenticating
	// requests,
	// allowing access to private repositories.
	Token string
	// Client overrides the HTTP client used for API requests. It defaults to
	// [transport.DefaultClient] if not set.
	Client *http.Client
}
