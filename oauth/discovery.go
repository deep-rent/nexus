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
	"fmt"
	"net/http"

	"github.com/deep-rent/nexus/router"
)

// AuthorizationServerMetadata represents the OAuth 2.0 Authorization Server
// Metadata payload (RFC 8414).
type AuthorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	KeySetURI                         string   `json:"jwks_uri,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

type DiscoveryConfig struct {
	Issuer                  string
	BaseURI                 string
	AuthorizationPath       string
	TokenPath               string
	KeySetPath              string
	IntrospectionPath       string
	RevocationPath          string
	DeviceAuthorizationPath string
	GrantTypesSupported     []string
	MaxAge                  int
}

type Discovery struct {
	meta   AuthorizationServerMetadata
	maxAge int
}

func NewDiscovery(cfg *DiscoveryConfig) *Discovery {
	baseURI := cfg.BaseURI

	return &Discovery{
		meta: AuthorizationServerMetadata{
			Issuer:                      baseURI,
			AuthorizationEndpoint:       baseURI + PathAuthorize,
			TokenEndpoint:               baseURI + PathToken,
			KeySetURI:                   baseURI + PathKeySet,
			RevocationEndpoint:          baseURI + PathRevoke,
			IntrospectionEndpoint:       baseURI + PathIntrospect,
			DeviceAuthorizationEndpoint: baseURI + PathDeviceAuthorization,
			GrantTypesSupported:         cfg.GrantTypesSupported,
			ResponseTypesSupported:      []string{"code"},
			TokenEndpointAuthMethodsSupported: []string{
				"client_secret_basic", "client_secret_post", "none",
			},
		},
		maxAge: cfg.MaxAge,
	}
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
	e.SetHeader("Cache-Control", fmt.Sprintf("public, max-age=%d", d.maxAge))

	return e.JSON(http.StatusOK, d.meta)
}

var _ router.Handler = (*Discovery)(nil)
