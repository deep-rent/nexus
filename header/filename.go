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

package header

import (
	"mime"
	"net/http"
	"strings"
)

// Filename extracts the intended filename from a Content-Disposition header.
//
// It automatically handles both the standard "filename" parameter and the
// RFC 6266 "filename*" parameter, which is used for non-ASCII (UTF-8) names.
// It returns an empty string if the header is missing, malformed, or does
// not contain a filename.
//
// The value is chosen by whoever sent the response, so it is reduced to a bare
// base name: directory components are stripped, and names that would resolve
// to a directory or carry a null byte are rejected. Without this, a header
// such as `attachment; filename="../../etc/passwd"` would hand the caller a
// path that escapes the directory it is joined to. The result is still
// untrusted input and should not be used as a path without further checks.
func Filename(h http.Header) string {
	v := h.Get("Content-Disposition")
	if v == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(v)
	if err != nil {
		return ""
	}
	// The filename* parameter is decoded automatically.
	return basename(params["filename"])
}

// basename reduces a filename supplied by a remote party to its last path
// element, rejecting values that cannot name a file.
func basename(name string) string {
	// Both separators are stripped regardless of the host platform, since the
	// sender may report a Windows path to a server running elsewhere.
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}

	name = strings.TrimSpace(name)
	if name == "." || name == ".." || strings.ContainsRune(name, 0) {
		return ""
	}
	return name
}
