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

package env_test

import (
	"testing"

	"github.com/deep-rent/nexus/sys/env"
)

func BenchmarkUnmarshal(b *testing.B) {
	mockEnv := map[string]string{
		"HOST":    "localhost",
		"PORT":    "9090",
		"TIMEOUT": "30",
		"DEBUG":   "true",
		"ROLES":   "admin;user;guest",
	}

	opts := []env.Option{
		env.WithLookup(func(k string) (string, bool) {
			v, ok := mockEnv[k]
			return v, ok
		}),
	}

	for b.Loop() {
		var cfg mockBenchConfig
		if err := env.Unmarshal(&cfg, opts...); err != nil {
			b.Fatalf("should not have returned an error: %v", err)
		}
	}
}

func BenchmarkExpand(b *testing.B) {
	mockEnv := map[string]string{
		"USER": "foo",
		"HOST": "bar",
		"PORT": "8080",
	}

	opts := []env.Option{
		env.WithLookup(func(k string) (string, bool) {
			v, ok := mockEnv[k]
			return v, ok
		}),
	}

	input := "user=$USER, pass=$$ECRET, dsn=${USER}@${HOST}:${PORT}"

	for b.Loop() {
		_, err := env.Expand(input, opts...)
		if err != nil {
			b.Fatalf("should not have returned an error: %v", err)
		}
	}
}
