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

// Package header provides a collection of utility functions for parsing,
// interpreting, and manipulating HTTP headers.
//
// The package includes helpers for common header-related tasks, such as:
//   - Parsing comma-separated directives (e.g., "max-age=3600").
//   - Parsing wildcard-aware content negotiation headers with q-factors.
//   - Parsing RFC 5988 Link headers to extract relations for API pagination.
//   - Extracting credentials from an Authorization header.
//   - Calculating cache lifetime from Cache-Control and Expires headers.
//   - Determining throttle delays from Retry-After and X-Ratelimit-* headers.
//
// It also provides a convenient [http.RoundTripper] implementation for
// automatically attaching a static set of headers to all outgoing requests.
package header
