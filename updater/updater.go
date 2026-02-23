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

// Package updater provides functionality to check for newer releases of an
// application on GitHub.
package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// Release represents a published release on GitHub.
type Release struct {
	Version string    `json:"tag_name"`
	URL     string    `json:"html_url"`
	Date    time.Time `json:"published_at"`
	Body    string    `json:"body"`
}

// Updater checks for updates on GitHub for a specific repository.
type Updater struct {
	repo      string
	current   string
	userAgent string
	client    *http.Client
}

// Option configures the Updater.
type Option func(*Updater)

// WithUserAgent sets the User-Agent header for requests.
func WithUserAgent(agent string) Option {
	return func(u *Updater) {
		u.userAgent = agent
	}
}

// WithClient sets a custom HTTP client.
func WithClient(client *http.Client) Option {
	return func(u *Updater) {
		u.client = client
	}
}

// New creates a new Updater.
//
// repo should be in the format "owner/repo" (e.g., "deep-rent/vouch").
// current is the current version string of the application (e.g., "v1.0.0" or "1.0.0").
func New(repo, current string, opts ...Option) *Updater {
	u := &Updater{
		repo:    repo,
		current: current,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(u)
	}
	return u
}

// Check queries the GitHub API for the latest release.
//
// It returns a Release if a newer version is available compared to the current
// one. It returns nil if the current version is up-to-date, if the current
// version string is invalid (e.g. "dev"), or if the latest release is older.
func (u *Updater) Check(ctx context.Context) (*Release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", u.repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if u.userAgent != "" {
		req.Header.Set("User-Agent", u.userAgent)
	}

	res, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch latest release: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned status: %s", res.Status)
	}

	var rel Release
	if err := json.NewDecoder(res.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode github response: %w", err)
	}

	v1 := normalize(u.current)
	v2 := normalize(rel.Version)

	if semver.IsValid(v1) && semver.Compare(v2, v1) > 0 {
		return &rel, nil
	}

	return nil, nil
}

// Check is a convenience function to check for updates in a single call.
func Check(ctx context.Context, repo, current string, opts ...Option) (*Release, error) {
	return New(repo, current, opts...).Check(ctx)
}

func normalize(v string) string {
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}
