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

package header_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/header"
)

// A filename is chosen by the remote server and must never escape the
// directory a caller joins it to.
func TestFilename_Traversal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want string
	}{
		{
			"relative traversal",
			`attachment; filename="../../etc/passwd"`,
			"passwd",
		},
		{
			"absolute path",
			`attachment; filename="/etc/shadow"`,
			"shadow",
		},
		{
			"windows path",
			`attachment; filename="..\\..\\windows\\system32\\config"`,
			"config",
		},
		{
			"bare parent",
			`attachment; filename=".."`,
			"",
		},
		{
			"bare dot",
			`attachment; filename="."`,
			"",
		},
		{
			"trailing separator",
			`attachment; filename="evil/"`,
			"",
		},
		{
			"plain name",
			`attachment; filename="report.pdf"`,
			"report.pdf",
		},
		{
			"utf-8 name",
			`attachment; filename*=UTF-8''%E2%82%AC%20rates.pdf`,
			"€ rates.pdf",
		},
		{
			"utf-8 name with traversal",
			`attachment; filename*=UTF-8''..%2F..%2Fsecret.pdf`,
			"secret.pdf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := http.Header{"Content-Disposition": []string{tt.give}}
			got := header.Filename(h)

			if got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}

			if strings.ContainsAny(got, `/\`) {
				t.Errorf("got %q; want no path separators", got)
			}
		})
	}
}

func TestFilename_Missing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		h    http.Header
	}{
		{"no header", http.Header{}},
		{
			"no filename",
			http.Header{"Content-Disposition": []string{"attachment"}},
		},
		{
			"malformed",
			http.Header{"Content-Disposition": []string{"attachment; ;"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := header.Filename(tt.h); got != "" {
				t.Errorf("got %q; want empty", got)
			}
		})
	}
}
