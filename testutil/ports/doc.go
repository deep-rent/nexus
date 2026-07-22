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

// Package ports provides test helpers for discovering available network ports
// and waiting for TCP servers to start listening.
//
// Tests that spin up real servers face two recurring problems: picking a port
// that is not already taken, and knowing when the server is actually ready to
// accept connections. This package solves both by asking the kernel for an
// unused port and by polling an address until a dial succeeds. All helpers
// fail the enclosing test on error, so call sites stay free of error handling.
//
// # Usage
//
// Use [Free] to obtain an available TCP port on the given host:
//
//	port := ports.Free(t, "127.0.0.1")
//
// Start a server on that port, then use [Wait] to block until it accepts
// connections:
//
//	go serve(port)
//	ports.Wait(t, "127.0.0.1", port)
//
// # Caveats
//
// [Free] releases the port before returning, so another process could claim
// it before the test binds to it. This race is inherent to port
// pre-allocation and rarely occurs in practice; keep the window small by
// binding to the port promptly. Where possible, prefer listening on port 0
// directly and reading the assigned address off the listener.
package ports
