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

package pass

// Option customizes a [Hasher] during construction with [New].
type Option func(*Hasher)

// WithAlgorithm registers an [Algorithm] for verification under its name.
// Records naming the algorithm verify against it; new hashes are not
// affected. Registering a second algorithm with the same name replaces the
// first.
//
// It panics if the algorithm is nil or unnamed, since both are startup
// configuration errors.
func WithAlgorithm(alg Algorithm) Option {
	return func(h *Hasher) { h.register(alg) }
}

// WithDefault registers an [Algorithm] like [WithAlgorithm] and
// additionally selects it for hashing new passwords.
//
// It panics if the algorithm is nil or unnamed, since both are startup
// configuration errors.
func WithDefault(alg Algorithm) Option {
	return func(h *Hasher) {
		h.register(alg)
		h.def = alg
	}
}
