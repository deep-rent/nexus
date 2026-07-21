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

// Package drivertest provides a backend-agnostic equivalence suite for the
// diff storage contracts. It exercises the shared semantics that every
// [diff.Handler] and [diff.Store] implementation must honor, so the mock and
// postgres drivers can be proven to behave identically without duplicating
// the scenarios in each package.
//
// The suite lives in its own package because it imports neither driver: each
// backend supplies a [Target] through a constructor and calls
// [RunEquivalence] from a thin test in its own package. This keeps the shared
// scenarios in one place while avoiding an import cycle between the drivers.
package drivertest
