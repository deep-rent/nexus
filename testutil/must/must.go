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

package must

import (
	"testing"
)

// Panic calls the given function and fails the test immediately unless it
// panics. It returns the recovered value so that callers can assert on
// the panic payload.
//
// Note that the recovered value is never nil: since Go 1.21, a panic(nil)
// surfaces as a [runtime.PanicNilError].
func Panic(t testing.TB, f func()) (r any) {
	t.Helper()
	defer func() {
		if r = recover(); r == nil {
			t.Fatal("should have panicked")
		}
	}()
	f()
	return
}
