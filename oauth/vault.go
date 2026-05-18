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
	"log/slog"
	"net/http"

	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/router"
)

type Vault struct {
	keySet jwk.Set
	logger *slog.Logger
}

// ServeHTTP handles the JSON Web Key Set endpoint (RFC 7517).
//
// It exposes the public keys used by the authorization server to sign tokens,
// allowing external resource servers and clients to verify signatures.
//
// Note: This endpoint is only enabled if a valid URL issuer was specified by
// the configured JWT signer.
func (v *Vault) ServeHTTP(e *router.Exchange) error {
	raw, err := jwk.WriteSet(v.keySet)
	if err != nil {
		id := router.ErrorID()

		v.logger.ErrorContext(
			e.Context(),
			"Failed to serialize key set",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to generate jwks",
			ID:          id,
		}
	}

	e.SetHeader("Content-Type", "application/jwk-set+json")
	e.SetHeader("Cache-Control", "public, max-age=3600")

	e.Status(http.StatusOK)
	_, err = e.W.Write(raw)

	return err
}

var _ router.Handler = (*Vault)(nil)
