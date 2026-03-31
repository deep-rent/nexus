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

package schema_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deep-rent/nexus/internal/schema"
)

func TestPostgres(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   []string
	}{
		{
			name:   "empty script",
			script: "",
			want:   nil,
		},
		{
			name:   "whitespace only",
			script: " \n\t ",
			want:   nil,
		},
		{
			name:   "single statement without semicolon",
			script: "SELECT 1",
			want:   []string{"SELECT 1"},
		},
		{
			name:   "single statement with semicolon",
			script: "SELECT 1;",
			want:   []string{"SELECT 1"},
		},
		{
			name:   "multiple statements",
			script: "SELECT 1; SELECT 2; SELECT 3;",
			want:   []string{"SELECT 1", "SELECT 2", "SELECT 3"},
		},
		{
			name:   "single line comment",
			script: "SELECT 1; -- ignore this ;\nSELECT 2;",
			want:   []string{"SELECT 1", "-- ignore this ;\nSELECT 2"},
		},
		{
			name:   "multi line comment",
			script: "SELECT 1; /* ignore \n ; \n */ SELECT 2;",
			want:   []string{"SELECT 1", "/* ignore \n ; \n */ SELECT 2"},
		},
		{
			name:   "nested multi line comment",
			script: "SELECT /* level 1 /* level 2 ; */ ; */ 1;",
			want:   []string{"SELECT /* level 1 /* level 2 ; */ ; */ 1"},
		},
		{
			name:   "single quotes",
			script: "SELECT 'some ; string'; SELECT 2;",
			want:   []string{"SELECT 'some ; string'", "SELECT 2"},
		},
		{
			name:   "escaped single quotes",
			script: "SELECT 'some '' ; '' string'; SELECT 2;",
			want:   []string{"SELECT 'some '' ; '' string'", "SELECT 2"},
		},
		{
			name:   "double quotes",
			script: `SELECT "some ; identifier"; SELECT 2;`,
			want:   []string{`SELECT "some ; identifier"`, `SELECT 2`},
		},
		{
			name:   "escaped double quotes",
			script: `SELECT "some "" ; "" identifier"; SELECT 2;`,
			want:   []string{`SELECT "some "" ; "" identifier"`, `SELECT 2`},
		},
		{
			name:   "dollar quotes empty tag",
			script: "SELECT $$some ; string$$; SELECT 2;",
			want:   []string{"SELECT $$some ; string$$", "SELECT 2"},
		},
		{
			name:   "dollar quotes named tag",
			script: "SELECT $func$some ; string$func$; SELECT 2;",
			want:   []string{"SELECT $func$some ; string$func$", "SELECT 2"},
		},
		{
			name:   "invalid dollar quote tag falls back to standard split",
			script: "SELECT $tag $some; string$tag $; SELECT 2;",
			want:   []string{"SELECT $tag $some", "string$tag $", "SELECT 2"},
		},
		{
			name:   "complex nested quote strings inside dollar quotes",
			script: "CREATE FUNCTION foo() RETURNS void AS $$ BEGIN SELECT 'some ; string'; END; $$ LANGUAGE plpgsql;",
			want:   []string{"CREATE FUNCTION foo() RETURNS void AS $$ BEGIN SELECT 'some ; string'; END; $$ LANGUAGE plpgsql"},
		},
		{
			name:   "comments inside strings",
			script: "SELECT '-- not a comment ;', '/* not a comment ; */';",
			want:   []string{"SELECT '-- not a comment ;', '/* not a comment ; */'"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := schema.Postgres([]byte(tc.script))
			assert.Equal(t, tc.want, actual)
		})
	}
}

func TestPostgres_TestData(t *testing.T) {
	tests := []struct {
		name string
		file string
		want int // Expected number of statements
	}{
		{
			name: "initial schema",
			file: "00001_initial_schema.up.sql",
			want: 6,
		},
		{
			name: "audit triggers",
			file: "00002_audit_triggers.up.sql",
			want: 3,
		},
		{
			name: "concurrent indexes",
			file: "00003_concurrent_indexes.up_notx.sql",
			want: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join("testdata", tc.file)
			content, err := os.ReadFile(path) //nolint:gosec
			require.NoError(t, err)

			actual := schema.Postgres(content)
			assert.Len(t, actual, tc.want)
		})
	}
}

func BenchmarkPostgres_Simple(b *testing.B) {
	script := []byte("SELECT 1; SELECT 2; SELECT 3;")

	b.ReportAllocs()

	for b.Loop() {
		_ = schema.Postgres(script)
	}
}

func BenchmarkPostgres_Complex(b *testing.B) {
	path := filepath.Join("testdata", "00002_audit_triggers.up.sql")
	script, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		_ = schema.Postgres(script)
	}
}

func BenchmarkPostgres_Massive(b *testing.B) {
	var script []byte
	stmt := []byte("INSERT INTO users (email) VALUES ('test@example.com');\n")
	for range 10000 {
		script = append(script, stmt...)
	}

	b.ReportAllocs()

	for b.Loop() {
		_ = schema.Postgres(script)
	}
}
