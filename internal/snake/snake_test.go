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

package snake_test

import (
	"testing"

	"github.com/deep-rent/nexus/internal/snake"
)

func TestToUpper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want string
	}{
		{"simple", "myVariable", "MY_VARIABLE"},
		{"acronym start", "APIService", "API_SERVICE"},
		{"acronym middle", "myAPIService", "MY_API_SERVICE"},
		{"acronym end", "serviceAPI", "SERVICE_API"},
		{"all caps", "ID", "ID"},
		{"single word", "test", "TEST"},
		{"empty string", "", ""},
		{"already snake", "MY_VARIABLE", "MY_VARIABLE"},
		{"leading lowercase", "aBC", "A_BC"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := snake.ToUpper(tt.give); got != tt.want {
				t.Errorf("ToUpper(%q) = %q; want %q", tt.give, got, tt.want)
			}
		})
	}
}

func TestToLower(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want string
	}{
		{"simple", "myVariable", "my_variable"},
		{"acronym start", "APIService", "api_service"},
		{"acronym middle", "myAPIService", "my_api_service"},
		{"acronym end", "serviceAPI", "service_api"},
		{"all caps", "ID", "id"},
		{"single word", "test", "test"},
		{"empty string", "", ""},
		{"already snake", "my_variable", "my_variable"},
		{"leading lowercase", "aBC", "a_bc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := snake.ToLower(tt.give); got != tt.want {
				t.Errorf("ToLower(%q) = %q; want %q", tt.give, got, tt.want)
			}
		})
	}
}
