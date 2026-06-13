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
	"context"

	"github.com/deep-rent/nexus/internal/rotor"
	"github.com/deep-rent/nexus/jose/jwk"
)

// StaticSource is a default [Source] implementation that holds a fixed set of
// keys and supports automatic key rotation using [rotor.Rotor].
type StaticSource struct {
	keys  []jwk.KeyPair
	rotor rotor.Rotor[jwk.KeyPair]
}

// NewStaticSource creates a new source that rotates through the provided keys.
// The active key rotates round-robin style on every call to Load.
// It panics if no keys are provided.
func NewStaticSource(keys ...jwk.KeyPair) *StaticSource {
	if len(keys) == 0 {
		panic("StaticSource requires at least one key")
	}
	return &StaticSource{
		keys:  keys,
		rotor: rotor.New(keys),
	}
}

// Load implements the [Source] interface.
// It retrieves the keys, placing the currently active key (via rotation)
// at the first index, followed by the remaining keys.
func (s *StaticSource) Load(ctx context.Context) ([]jwk.KeyPair, error) {
	active := s.rotor.Next()

	res := make([]jwk.KeyPair, 0, len(s.keys))
	res = append(res, active)

	for _, k := range s.keys {
		// Compare by KeyID to avoid adding the active key again
		if k.KeyID() != "" && active.KeyID() != "" {
			if k.KeyID() != active.KeyID() {
				res = append(res, k)
			}
		} else {
			// Fallback if both are empty (should not happen with proper keys)
			if k != active { // Pointer comparison
				res = append(res, k)
			}
		}
	}

	return res, nil
}
