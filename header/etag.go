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

import "strings"

// ETag returns the entity tag carried by the ETag header, or an empty string
// if there is none. The value is returned as sent, including its quotes and
// any weak-comparison prefix.
func ETag(h Getter) string {
	return strings.TrimSpace(h.Get("ETag"))
}

// Getter is the subset of [net/http.Header] these helpers read from. Both
// request and response headers satisfy it.
type Getter interface {
	// Get returns the first value associated with the given key.
	Get(key string) string
}

// Quote wraps an entity tag in the double quotes that RFC 9110 requires,
// unless it already carries them or is marked weak. It is a convenience for
// callers deriving a tag from a version number or hash:
//
//	h.Set("ETag", header.Quote(strconv.FormatInt(version, 10)))
func Quote(tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return ""
	}
	if strings.HasPrefix(tag, `"`) && strings.HasSuffix(tag, `"`) {
		return tag
	}
	if strings.HasPrefix(tag, `W/"`) && strings.HasSuffix(tag, `"`) {
		return tag
	}
	return `"` + tag + `"`
}

// MatchETag reports whether an If-None-Match header value matches the given
// entity tag.
//
// It applies the weak comparison prescribed for If-None-Match by RFC 9110,
// section 13.1.2: a "W/" prefix on either side is ignored, and "*" matches
// any current representation. A caller that has a tag for the resource can
// answer 304 Not Modified whenever this returns true:
//
//	tag := header.Quote(version)
//	w.Header().Set("ETag", tag)
//	if header.MatchETag(r.Header.Get("If-None-Match"), tag) {
//		w.WriteHeader(http.StatusNotModified)
//		return
//	}
//
// An empty header never matches, so a request that carries no validator is
// always answered in full.
func MatchETag(value, tag string) bool {
	value = strings.TrimSpace(value)
	if value == "" || tag == "" {
		return false
	}
	if value == "*" {
		return true
	}

	tag = weak(tag)
	for candidate := range fields(value, ',') {
		if weak(candidate) == tag {
			return true
		}
	}
	return false
}

// weak strips the weakness prefix from an entity tag, reducing it to the form
// used for weak comparison.
func weak(tag string) string {
	return strings.TrimPrefix(strings.TrimSpace(tag), `W/`)
}
