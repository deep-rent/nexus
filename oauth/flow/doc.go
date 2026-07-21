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

// Package flow sequences a multi-step login as a chain of authentication
// factors decided at runtime.
//
// It generalizes a fixed "password then one-time password" login into an
// ordered list of [Step] values — text, mail, or push challenges today, TOTP or
// others later — produced per-login by a [Plan]. The [Coordinator] drives the
// chain: [Coordinator.Begin] mints a transaction and activates the first step,
// [Coordinator.Continue] verifies the active step and advances, and
// [Coordinator.Act] runs an out-of-band action such as resending a code.
//
// # Design
//
// The engine is transport-agnostic and store-backed, like the otp challenge
// engine it composes: it neither speaks HTTP nor throttles, reporting logical
// results as a [Result] and reserving Go errors for storage and delivery
// failures. The identifying factor (a password, say) is verified by the caller
// before the flow begins; a transaction is minted only once further steps
// remain, so an unauthenticated request never creates server state.
//
// The [Plan] is re-run on every continuation, so a change to a subject's
// enrolled factors — or a revocation — takes effect mid-login. Progress is
// tracked by the set of completed step IDs rather than an index, so adding or
// removing a step between calls is handled gracefully: a newly planned step is
// run, and a step dropped from the plan is skipped.
//
// # Steps
//
// A [Step] owns its own per-step state; the transaction only records which
// steps are done. A step derives whatever it needs from the raw transaction
// handle passed to it — for example, an otp-backed step keys its challenge on a
// value derived from the handle and the step ID, so the client holds a single
// token for the whole flow.
package flow
