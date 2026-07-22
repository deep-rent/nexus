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

// Package snake provides functions for converting strings between camelCase and
// snake_case formats.
//
// It handles transitions between lowercase letters, uppercase letters, and
// digits to produce idiomatic snake_case or SCREAMING_SNAKE_CASE strings. The
// implementation is specifically tuned for ASCII character sets and manages
// acronyms by detecting transitions from sequences of uppercase letters to a
// new word.
//
// # Usage
//
// Use [ToLower] for standard snake_case and [ToUpper] for constant-style
// uppercase snake_case.
//
// Example:
//
//	low := snake.ToLower("JSONData") // "json_data"
//	up  := snake.ToUpper("myVariable") // "MY_VARIABLE"
package snake
