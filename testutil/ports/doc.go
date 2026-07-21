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

// Package ports provides integration test helpers for network port management.
//

// Package ports offers utilities to find available network ports and block
// until those ports begin accepting connections. These helpers are primarily
// intended for integration testing scenarios where services are started on
// dynamic ports to avoid collisions.
//
// # Usage
//
// Find a free port and wait for a service to become ready on it.
//
// Example:
//
//	port := ports.FreeT(t)
//	go startService(port)
//	ports.WaitT(t, "127.0.0.1", port)
package ports
