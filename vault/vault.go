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
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/rotor"
)

// Vault represents a secure retrieval mechanism for cryptographic signing keys.
// It abstracts away the underlying implementation details of external sources
// like KMS, HSM, or HashiCorp Vault.
type Vault interface {
	Keys() jwk.Set

	// Next retrieves the currently active [jwk.KeyPair] intended for signing
	// new tokens.
	Next() jwk.KeyPair
}

type vault struct {
	pub jwk.Set
	prv rotor.Rotor[jwk.KeyPair]
}

func New(keys []jwk.KeyPair, strategy rotor.Strategy) Vault {
	pub := make([]jwk.Key, 0, len(keys))
	for i, k := range keys {
		pub[i] = k
	}
	prv := rotor.New(strategy, keys)
	return &vault{
		pub: jwk.NewSet(pub...),
		prv: prv,
	}
}

func (v *vault) Keys() jwk.Set     { return v.pub }
func (v *vault) Next() jwk.KeyPair { return v.prv.Next() }
