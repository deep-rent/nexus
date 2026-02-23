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
	"encoding/json/v2"
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

// Config holds the configuration for the Updater.
type Config struct {
	Owner     string        // GitHub repository owner (required).
	Repo      string        // GitHub repository name (required).
	Current   string        // Current version of the application (required).
	UserAgent string        // User-Agent header (optional).
	Timeout   time.Duration // Request timeout (optional, defaults to 10s).
}

// Updater checks for updates on GitHub for a specific repository.
type Updater struct {
	cfg    Config
	client *http.Client
}

// New creates a new Updater with the given configuration.
func New(cfg Config) *Updater {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &Updater{
		cfg: cfg,
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
// if the current version is up-to-date, if the current version string is not
// valid semantic version, or if the latest release is older or equal.
func (u *Updater) Check(ctx context.Context) (*Release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", u.cfg.Owner, u.cfg.Repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if u.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", u.cfg.UserAgent)
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

	var rel Release
	if err := json.UnmarshalRead(res.Body, &rel); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	vCurrent := normalize(u.cfg.Current)
	vLatest := normalize(rel.Version)

	if semver.IsValid(vCurrent) && semver.Compare(vLatest, vCurrent) > 0 {
		return &rel, nil
	}

	return nil, nil
}

// Check is a convenience function to check for updates in a single call.
func Check(ctx context.Context, cfg Config) (*Release, error) {
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
