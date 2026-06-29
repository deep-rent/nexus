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
	"reflect"
	"testing"
	"time"

	"github.com/deep-rent/nexus/env"
)



func TestUnmarshal(t *testing.T) {
	t.Parallel()


	tests := []struct {
		name    string
		vars    map[string]string
		opts    []env.Option
		give    any
		want    any
		wantErr bool
	}{
		{
			name: "global prefix",
			vars: map[string]string{"APP_V": "foo"},
			opts: []env.Option{env.WithPrefix("APP_")},
			give: &struct{V string}{},
			want: &struct{V string}{"foo"},
		},

	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := tt.opts
			opts = append(opts, env.WithLookup(func(k string) (string, bool) {
				v, ok := tt.vars[k]
				return v, ok
			}))
			err := env.Unmarshal(tt.give, opts...)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Unmarshal() error = nil; want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal() unexpected error: %v", err)
			}
			if !reflect.DeepEqual(tt.give, tt.want) {
				t.Errorf("Unmarshal() = %v; want %v", tt.give, tt.want)
			}
		})
	}
}

func TestUnmarshal_Errors(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		if err := env.Unmarshal(nil); err == nil {
			t.Error("Unmarshal(nil) error = nil; want non-nil")
		}
	})

	t.Run("not a pointer", func(t *testing.T) {
		t.Parallel()
		var s struct{}
		if err := env.Unmarshal(s); err == nil {
			t.Error("Unmarshal(struct) error = nil; want non-nil")
		}
	})

	t.Run("not a pointer to a struct", func(t *testing.T) {
		t.Parallel()
		var i int
		if err := env.Unmarshal(&i); err == nil {
			t.Error("Unmarshal(*int) error = nil; want non-nil")
		}
	})
}

func TestExpand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		vars    map[string]string
		opts    []env.Option
		give    string
		want    string
		wantErr bool
	}{
		{
			name: "no variables",
			give: "foo bar baz",
			want: "foo bar baz",
		},
		{
			name: "simple bracket expansion",
			vars: map[string]string{"FOO": "bar"},
			give: "hello ${FOO}",
			want: "hello bar",
		},
		{
			name: "simple unbracketed expansion",
			vars: map[string]string{"FOO": "bar"},
			give: "hello $FOO",
			want: "hello bar",
		},
		{
			name: "unbracketed expansion stopping at non-identifier",
			vars: map[string]string{"FOO": "bar"},
			give: "$FOO-baz",
			want: "bar-baz",
		},
		{
			name: "unbracketed expansion with numbers and underscores",
			vars: map[string]string{"VAR_123": "bar"},
			give: "hello $VAR_123",
			want: "hello bar",
		},
		{
			name: "multiple expansions",
			vars: map[string]string{"FOO": "bar", "BAZ": "qux"},
			give: "${FOO} ${BAZ}",
			want: "bar qux",
		},
		{
			name: "escaped dollar sign",
			vars: map[string]string{},
			give: "this is not a var: $$FOO",
			want: "this is not a var: $FOO",
		},
		{
			name: "lone dollar sign",
			vars: map[string]string{},
			give: "a lone $ sign",
			want: "a lone $ sign",
		},
		{
			name: "lone dollar sign before number",
			vars: map[string]string{},
			give: "cost is $5",
			want: "cost is $5",
		},
		{
			name: "variable at start",
			vars: map[string]string{"FOO": "bar"},
			give: "${FOO} baz",
			want: "bar baz",
		},
		{
			name: "variable at end",
			vars: map[string]string{"FOO": "bar"},
			give: "baz ${FOO}",
			want: "baz bar",
		},
		{
			name: "bracketed with prefix",
			vars: map[string]string{"APP_FOO": "bar"},
			opts: []env.Option{env.WithPrefix("APP_")},
			give: "${FOO}",
			want: "bar",
		},
		{
			name: "unbracketed with prefix",
			vars: map[string]string{"APP_FOO": "bar"},
			opts: []env.Option{env.WithPrefix("APP_")},
			give: "$FOO",
			want: "bar",
		},
		{
			name:    "bracketed variable not set",
			vars:    map[string]string{},
			give:    "${FOO}",
			wantErr: true,
		},
		{
			name:    "unbracketed variable not set",
			vars:    map[string]string{},
			give:    "$FOO",
			wantErr: true,
		},
		{
			name:    "unclosed bracket",
			vars:    map[string]string{},
			give:    "${FOO",
			wantErr: true,
		},
		{
			name: "empty string",
			give: "",
			want: "",
		},
		{
			name: "complex string",
			vars: map[string]string{"USER": "foo", "HOST": "bar", "PORT": "8080"},
			give: "user=$USER, pass=$$ECRET, dsn=${USER}@${HOST}:${PORT}",
			want: "user=foo, pass=$ECRET, dsn=foo@bar:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := tt.opts
			opts = append(opts, env.WithLookup(func(k string) (string, bool) {
				v, ok := tt.vars[k]
				return v, ok
			}))
			got, err := env.Expand(tt.give, opts...)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Expand() error = nil; want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Expand() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Expand() = %q; want %q", got, tt.want)
			}
		})
	}
}

type mockBenchConfig struct {
	Host    string        `env:",required"`
	Port    int           `env:",default:8080"`
	Timeout time.Duration `env:",unit:s"`
	Debug   bool
	Roles   []string `env:",split:';'"`
}

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
			b.Fatalf("Unmarshal() unexpected error: %v", err)
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
			b.Fatalf("Expand() unexpected error: %v", err)
		}
	}
}
