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

package diff_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"
	"testing"
	"uuid"

	"github.com/deep-rent/nexus/diff"
	"github.com/deep-rent/nexus/internal/hlc"
	"github.com/deep-rent/nexus/valid"
)

func TestStamp_RoundTrip(t *testing.T) {
	t.Parallel()

	want := hlc.Time(hlc.Max) // 2^53 - 1, the critical precision boundary

	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshaling: should not have returned an error: %v", err)
	}
	if got := string(b); got != "9007199254740991" {
		t.Errorf("encoding: got %s; want 9007199254740991", got)
	}

	var got diff.Stamp
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshaling: should not have returned an error: %v", err)
	}
	if got != want {
		t.Errorf("round trip: got %d; want %d", got, want)
	}
}

func TestCursor_RoundTrip(t *testing.T) {
	t.Parallel()

	want := diff.Cursor(1<<53 - 1)

	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshaling: should not have returned an error: %v", err)
	}

	var got diff.Cursor
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshaling: should not have returned an error: %v", err)
	}
	if got != want {
		t.Errorf("round trip: got %d; want %d", got, want)
	}
}

func TestChange_Validate(t *testing.T) {
	t.Parallel()

	doc := jsontext.Value(`{"id":"019f66c1-7949-77ea-93bd-0d45df4542ee"}`)

	ok := diff.Change{
		ID:     uuid.NewV7(),
		Action: diff.ActionUpsert,
		Type:   "asset",
		Data:   doc,
		Time:   1,
	}

	tests := []struct {
		name   string
		mutate func(c *diff.Change)
		field  string
	}{
		{
			name:   "nil mutation id",
			mutate: func(c *diff.Change) { c.ID = uuid.Nil() },
			field:  "id",
		},
		{
			name:   "non-v7 mutation id",
			mutate: func(c *diff.Change) { c.ID = uuid.NewV4() },
			field:  "id",
		},
		{
			name:   "unknown action",
			mutate: func(c *diff.Change) { c.Action = "replace" },
			field:  "action",
		},
		{
			name:   "empty type",
			mutate: func(c *diff.Change) { c.Type = "" },
			field:  "type",
		},
		{
			name:   "missing data",
			mutate: func(c *diff.Change) { c.Data = nil },
			field:  "data",
		},
		{
			name:   "zero time",
			mutate: func(c *diff.Change) { c.Time = 0 },
			field:  "time",
		},
		{
			name:   "oversized time",
			mutate: func(c *diff.Change) { c.Time = hlc.Max + 1 },
			field:  "time",
		},
	}

	if err := valid.Test(&ok); err != nil {
		t.Fatalf("for a valid change: should not have returned an error: %v",
			err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := ok
			tt.mutate(&c)

			err := valid.Test(&c)
			if err == nil {
				t.Fatal("should have returned a validation error")
			}
			if _, found := err[tt.field]; !found {
				t.Errorf("got error for %v; want field %q", err, tt.field)
			}
		})
	}
}

func TestRequest_Validate(t *testing.T) {
	t.Parallel()

	t.Run("negative since", func(t *testing.T) {
		t.Parallel()
		r := diff.Request{Since: -1}

		err := valid.Test(&r)
		if err == nil {
			t.Fatal("should have returned a validation error")
		}
		if _, found := err["since"]; !found {
			t.Errorf("got error for %v; want field %q", err, "since")
		}
	})

	t.Run("negative limit", func(t *testing.T) {
		t.Parallel()
		r := diff.Request{Limit: -5}

		err := valid.Test(&r)
		if err == nil {
			t.Fatal("should have returned a validation error")
		}
		if _, found := err["limit"]; !found {
			t.Errorf("got error for %v; want field %q", err, "limit")
		}
	})

	t.Run("nested change paths", func(t *testing.T) {
		t.Parallel()
		r := diff.Request{
			Changes: []diff.Change{{
				ID:     uuid.NewV7(),
				Action: diff.ActionUpsert,
				Type:   "asset",
				Data:   jsontext.Value(`{}`),
				Time:   1,
			}, {
				// Invalid: missing everything.
			}},
		}

		err := valid.Test(&r)
		if err == nil {
			t.Fatal("should have returned a validation error")
		}
		for path := range err {
			if !strings.HasPrefix(path, "changes[1].") {
				t.Errorf("got path %q; want prefix %q", path, "changes[1].")
			}
		}
	})
}

func TestRequest_Decode(t *testing.T) {
	t.Parallel()

	in := `{
		"since": 7662800000000000,
		"limit": 200,
		"changes": [{
			"id": "019f66e2-5f89-77c2-bdb0-536d00378dc6",
			"action": "upsert",
			"type": "asset",
			"data": {"id": "019f66c1-7949-77ea-93bd-0d45df4542ee"},
			"time": 7662807846085459
		}]
	}`

	var req diff.Request
	if err := json.Unmarshal([]byte(in), &req); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if got, want := req.Since, diff.Cursor(7662800000000000); got != want {
		t.Errorf("since: got %d; want %d", got, want)
	}
	if got, want := len(req.Changes), 1; got != want {
		t.Fatalf("changes: got %d; want %d", got, want)
	}
	c := req.Changes[0]
	if got, want := c.Action, diff.ActionUpsert; got != want {
		t.Errorf("action: got %q; want %q", got, want)
	}
	if got, want := c.Time, diff.Stamp(7662807846085459); got != want {
		t.Errorf("time: got %d; want %d", got, want)
	}
	if got, want := c.ID.String(),
		"019f66e2-5f89-77c2-bdb0-536d00378dc6"; got != want {
		t.Errorf("id: got %q; want %q", got, want)
	}
}
