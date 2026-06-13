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

package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/router"
)

// Provider exposes the public keys of a [Vault] as a JSON Web Key Set (JWKS).
// It implements [router.Handler] and caches the generated JWKS representation.
type Provider struct {
	vault Vault

	mu      sync.RWMutex
	jwks    []byte
	etag    string
	lastMod time.Time
}

// NewProvider creates a new [Provider] wrapping the given [Vault].
func NewProvider(v Vault) *Provider {
	return &Provider{
		vault: v,
	}
}

// ServeHTTP implements [router.Handler]. It serves the JWKS with appropriate
// caching headers (ETag, Last-Modified) and handles conditional requests.
func (p *Provider) ServeHTTP(e *router.Exchange) error {
	ctx := e.Context()
	
	// Collect keys from the vault. Keys() returns an iterator.
	seq, err := p.vault.Keys(ctx)
	if err != nil {
		return err
	}

	var pub []jwk.Key
	for k := range seq {
		pub = append(pub, k)
	}

	set := jwk.NewSet(pub...)

	body, err := jwk.WriteSet(set)
	if err != nil {
		return err
	}

	hash := sha256.Sum256(body)
	etag := `W/"` + hex.EncodeToString(hash[:]) + `"`

	p.mu.Lock()
	if p.etag != etag {
		p.etag = etag
		p.jwks = body
		p.lastMod = time.Now().UTC()
	}
	lastMod := p.lastMod
	jwks := p.jwks
	p.mu.Unlock()

	if v := e.GetHeader("If-None-Match"); v != "" {
		if v == etag {
			e.Status(http.StatusNotModified)
			return nil
		}
	} else if v := e.GetHeader("If-Modified-Since"); v != "" {
		if t, err := time.Parse(http.TimeFormat, v); err == nil {
			if !lastMod.After(t.Add(time.Second)) { // Ignore sub-second precision
				e.Status(http.StatusNotModified)
				return nil
			}
		}
	}

	e.SetHeader("Content-Type", "application/jwk-set+json")
	e.SetHeader("ETag", etag)
	e.SetHeader("Last-Modified", lastMod.Format(http.TimeFormat))
	e.Status(http.StatusOK)

	_, err = e.W.Write(jwks)
	return err
}

var _ router.Handler = (*Provider)(nil)
