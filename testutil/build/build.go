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

// Package build provides test helpers for compiling Go binaries.
// It ensures that build artifacts are isolated and automatically cleaned up
// after the tests finish.
package build

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// Binary compiles the Go source code located at src and writes the resulting
// executable to dst within a temporary directory. It returns the absolute
// path to the compiled binary. The test framework automatically removes the
// executable and its directory when the test completes.
func Binary(t testing.TB, src string, dst string) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), dst)
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}

	cmd := exec.Command("go", "build", "-o", exe, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build %s: %v\n%s", dst, err, out)
	}

	return exe
}
