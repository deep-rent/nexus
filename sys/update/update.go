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
	"context"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/deep-rent/nexus/net/transport"
)

// Release represents a published release on GitHub.
type Release struct {
	// Version is the tag name of the release (e.g., "v1.0.0").
	Version string `json:"tag_name"`
	// URL is the web address to view the release on GitHub.
	URL string `json:"html_url"`
	// Published is the timestamp the release was published on GitHub.
	Published time.Time `json:"published_at"`
	// Notes contains the release notes or description.
	Notes string `json:"body"`
}

// Updater checks for updates on GitHub for a specific repository.
type Updater struct {
	// baseURL is the API endpoint for release lookups.
	baseURL string
	// owner is the GitHub user or organization.
	owner string
	// repo is the GitHub project name.
	repo string
	// current is the normalized current version of the application.
	current string
	// userAgent is the identifying string sent in the HTTP header.
	userAgent string
	// token is the GitHub PAT for authentication.
	token string
	// client is the HTTP client for making API requests.
	client *http.Client
}

// New creates a new [Updater] with the given configuration.
//
// Requests use [transport.DefaultClient] unless [Config.Client] overrides it.
// It panics if the configuration is missing required fields or if the current
// version string is
// not a valid semantic version.
func New(cfg *Config) *Updater {
	if cfg.Owner == "" {
		panic("owner is required")
	}
	if cfg.Repo == "" {
		panic("repository is required")
	}
	if cfg.Current == "" {
		panic("current version is required")
	}
	current := normalize(cfg.Current)
	if !semver.IsValid(current) {
		panic(fmt.Sprintf(
			"current version %q is not a valid semver",
			cfg.Current,
		))
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}

	client := cfg.Client
	if client == nil {
		client = transport.DefaultClient
	}

	return &Updater{
		baseURL:   baseURL,
		owner:     cfg.Owner,
		repo:      cfg.Repo,
		current:   current,
		userAgent: cfg.UserAgent,
		token:     cfg.Token,
		client:    client,
	}
}

// Check queries the GitHub Releases API to determine if a newer version exists.
//
// It compares the latest release tag against the current version using semantic
// versioning. It returns a [Release] if a newer version is found. It returns
// nil if the current version is up-to-date or if the latest release is older or
// equal.
func (u *Updater) Check(ctx context.Context) (*Release, error) {
	endpoint, err := url.JoinPath(
		u.baseURL,
		"repos",
		u.owner,
		u.repo,
		"releases",
		"latest",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if u.userAgent != "" {
		req.Header.Set("User-Agent", u.userAgent)
	}
	if u.token != "" {
		req.Header.Set("Authorization", "Bearer "+u.token)
	}

	res, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest release: %w", err)
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if code := res.StatusCode; code != http.StatusOK {
		return nil, fmt.Errorf("unexpected status from github api: %d", code)
	}

	var r Release
	if err := json.UnmarshalRead(res.Body, &r); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	v := r.Version
	latest := normalize(v)

	if !semver.IsValid(latest) {
		return nil, fmt.Errorf("latest version %q is not a valid semver", v)
	}

	if semver.Compare(latest, u.current) > 0 {
		return &r, nil
	}

	return nil, nil
}

// Check is a convenience function to check for updates in a single call.
//
// It creates a temporary [update] with the provided config and calls its
// [update.Check] method.
func Check(ctx context.Context, cfg *Config) (*Release, error) {
	return New(cfg).Check(ctx)
}

// normalize ensures the version string has a "v" prefix for the semver package.
func normalize(v string) string {
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}
