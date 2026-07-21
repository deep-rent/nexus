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

// Package vault provides secure retrieval and rotation of cryptographic keys.
//

// Package vault manages a collection of JSON Web Keys (JWK) for signing and
// verification. The primary abstraction is the [Vault] interface, which
// abstracts away underlying key sources (like Kubernetes Secrets or KMS)
// and handles key rotation through a [rotor.Strategy].
//
// # Usage
//
// The vault is typically initialized from a JSON configuration array containing
// PEM-encoded keys, and can seamlessly integrate with HTTP routers to serve
// JWKS endpoints:
//
//   - [Load]: Parses a JSON configuration array to initialize a [Vault].
//   - [LoadFile]: Shortcut for loading data configuration from the filesystem.
//   - [Handler]: Creates an HTTP handler to serve the public keys as a JWK Set.
//
// Example:
//
//	v, err := vault.LoadFile("/etc/secrets/keys.json", rotor.Sequential)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	key := v.Next()
//	sig, err := key.Sign(context.Background(), payload)
//
//	r := router.New()
//	r.HandleFunc("GET /.well-known/jwks.json", vault.Handler(v))
package vault
