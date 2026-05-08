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
//
// Package build offers utilities for compiling Go source code during tests. It
// ensures that build artifacts are isolated and automatically cleaned up after
// the tests finish by leveraging the testing framework's temporary directory
// management.
//
// # Usage
//
// Call the [Binary] function within a test to compile a target program.
//
// Example:
//
//	func TestIntegration(t *testing.T) {
//	    exe := build.Binary(t, "./cmd/app", "app-bin")
//	    cmd := exec.Command(exe)
//	    // ... run and test the binary ...
//	}
package build

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// Binary compiles Go source code and returns the path to the executable.
//
// It compiles the code located at the src directory and writes the resulting
// executable to dst within a temporary directory. The test framework
// automatically removes the executable and its directory when the test
// completes. It appends the ".exe" suffix on Windows systems.
func Binary(t testing.TB, src, dst string) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), dst)
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}

	// Compile the current directory but execute the command inside the src
	// directory. This ensures Go respects the module context of the target
	// program.
	cmd := exec.Command("go", "build", "-o", exe, ".") //nolint:gosec
	cmd.Dir = src

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build %s: %v\n%s", dst, err, out)
	}

	return exe
}
