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

package oauth

import (
	"net/http"

	"github.com/deep-rent/nexus/router"
)

type DiscoveryConfig struct {

}

type Discovery struct {
	meta AuthorizationServerMetadata
}

// ServeHTTP handles the OAuth 2.0 Authorization Server Metadata endpoint
// (RFC 8414) for endpoint discovery.
//
// Note: This endpoint is only enabled if a valid URL issuer was specified by
// the configured [jwt.Signer].
//
// The returned metadata dynamically includes endpoints for token revocation,
// introspection, and device authorization only if the provider is correctly
// configured or the respective grants are registered.
func (d *Discovery) ServeHTTP(e *router.Exchange) error {
	e.SetHeader("Cache-Control", "public, max-age=3600")

	return e.JSON(http.StatusOK, d.meta)
}

var _ router.Handler = (*Discovery)(nil)
