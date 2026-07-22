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

// Package must provides test assertions that fail the enclosing test unless
// a required condition holds.
//
// # Usage
//
// Use [Panic] to assert that a function panics. While an unexpected panic
// fails a test on its own, the inverse does not hold: code that is required
// to panic but silently returns goes unnoticed. [Panic] closes that gap and
// hands back the recovered value for further inspection:
//
//	r := must.Panic(t, func() { migrate.New() })
//	if r != "source is required" {
//		t.Errorf("got panic %v; want %q", r, "source is required")
//	}
package must
