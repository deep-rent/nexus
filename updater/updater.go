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

// Package updater provides a simple mechanism to check for newer releases of an
// application hosted on GitHub.
//
// It queries the GitHub Releases API and compares the latest release tag
// against the current application version using semantic versioning.
package updater

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// Default configuration values for the updater.
const (
	// DefaultBaseURL is the default GitHub API base URL.
	DefaultBaseURL = "https://api.github.com"
	// DefaultTimeout is the default timeout for HTTP requests.
	DefaultTimeout = 5 * time.Second
)

// Release represents a published release on GitHub.
type Release struct {
	// Version is the tag name of the release (e.g., "v1.0.0").
	Version string `json:"tag_name"`
	// URL to view the release on GitHub.
	URL string `json:"html_url"`
	// Published is the timestamp the release was published on GitHub.
	Published time.Time `json:"published_at"`
	// Notes contains the release notes or description.
	Notes string `json:"body"`
}

// Config holds the configuration for the Updater.
type Config struct {
	// BaseURL is the base URL for the GitHub API. It defaults to DefaultBaseURL
	// if not set. This is primarily used for testing purposes.
	BaseURL string

	// Owner is the GitHub repository owner (required).
	Owner string

	// Repo is the name of the GitHub repository. (required).
	Repo string

	// Current is the current version string of the application (required).
	Current string

	// UserAgent is the value for the User-Agent header sent with requests.
	// If empty, no User-Agent header is sent.
	UserAgent string

	// Timeout is the time limit for requests made by the updater.
	// It defaults to 5 seconds if not set.
	Timeout time.Duration
}

// Updater checks for updates on GitHub for a specific repository.
type Updater struct {
	baseURL   string
	owner     string
	repo      string
	current   string
	userAgent string
	client    *http.Client
}

// New creates a new Updater with the given configuration.
//
// It initializes the HTTP client with the specified timeout. It panics if the
// configuration is invalid (missing required fields) or if the current version
// string is not a valid semantic version.
func New(cfg *Config) *Updater {
	if cfg.Owner == "" {
		panic("updater: owner is required")
	}
	if cfg.Repo == "" {
		panic("updater: repo is required")
	}
	if cfg.Current == "" {
		panic("updater: current version is required")
	}
	current := normalize(cfg.Current)
	if !semver.IsValid(current) {
		panic(fmt.Sprintf(
			"updater: current version %q is not a valid semver",
			cfg.Current,
		))
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	return &Updater{
		baseURL:   baseURL,
		owner:     cfg.Owner,
		repo:      cfg.Repo,
		current:   current,
		userAgent: cfg.UserAgent,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Check queries the GitHub Releases API to determine if a newer version is
// available.
//
// It compares the latest release tag against the current version using semantic
// versioning. It returns a Release if a newer version is found. It returns nil
// if the current version is up-to-date or if the latest release is older or
// equal. It returns an error if the GitHub API request fails or if the latest
// release tag is not a valid semantic version.
func (u *Updater) Check(ctx context.Context) (*Release, error) {
	url := fmt.Sprintf(
		"%s/repos/%s/%s/releases/latest",
		u.baseURL, u.owner, u.repo,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if u.userAgent != "" {
		req.Header.Set("User-Agent", u.userAgent)
	}

	res, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest release: %w", err)
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status from github api: %s", res.Status)
	}

	var r Release
	if err := json.UnmarshalRead(res.Body, &r); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	latest := normalize(r.Version)

	if !semver.IsValid(latest) {
		return nil, fmt.Errorf("latest version %q is not a valid semver", r.Version)
	}

	if semver.Compare(latest, u.current) > 0 {
		return &r, nil
	}

	return nil, nil
}

// Check is a convenience function to check for updates in a single call.
// It creates a temporary Updater with the provided config and calls its Check
// method.
func Check(ctx context.Context, cfg *Config) (*Release, error) {
	return New(cfg).Check(ctx)
}

// normalize ensures the version string has a "v" prefix, which is required by
// the semver package.
func normalize(v string) string {
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}
