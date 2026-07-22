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

// Package tag provides utility for parsing Go struct tags that follow a
// comma-separated key-value option format.
//
// This format is similar to the `json` tag used in the standard library. The
// package handles complex cases where options may contain nested values or
// quoted strings, ensuring that commas within quotes do not break the parsing
// logic.
//
// # Usage
//
// Use [Parse] to initialize a tag and the [Tag.Opts] iterator to process
// individual options.
//
// Example:
//
//	const raw = "user_id,omitempty,default:'anonymous,guest'"
//	t := tag.Parse(raw)
//	// t.Name is "user_id"
//
//	for k, v := range t.Opts() {
//		// Yields:
//		// "omitempty", ""
//		// "default", "anonymous,guest"
//	}
package tag
