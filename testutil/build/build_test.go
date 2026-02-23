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

package build_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/deep-rent/nexus/testutil/build"
	"github.com/stretchr/testify/require"
)

func TestBinary(t *testing.T) {
	src := t.TempDir()

	// Create a dummy go.mod so the directory is a valid Go module.
	mod := []byte("module dummy\n\ngo 1.24\n")
	err := os.WriteFile(filepath.Join(src, "go.mod"), mod, 0644)
	require.NoError(t, err)

	// Create the main package.
	code := []byte("package main\nfunc main() {}\n")
	err = os.WriteFile(filepath.Join(src, "main.go"), code, 0644)
	require.NoError(t, err)

	// Build the directory.
	exe := build.Binary(t, src, "testbin")

	// Verify the executable was created.
	stat, err := os.Stat(exe)
	require.NoError(t, err)
	require.False(t, stat.IsDir())
}
