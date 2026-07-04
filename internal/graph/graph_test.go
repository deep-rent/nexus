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

package graph_test

import (
	"errors"
	"testing"

	"github.com/deep-rent/nexus/internal/graph"
)

func TestNew(t *testing.T) {
	t.Parallel()

	g := graph.New[int]()
	if g == nil {
		t.Fatalf("expected non-nil graph")
	}
}

func TestGraph_Sort(t *testing.T) {
	t.Parallel()
	t.Run("Valid DAG", func(t *testing.T) {
		t.Parallel()
		g := graph.New[string]()

		g.AddEdge("baz", "bar")
		g.AddEdge("bar", "foo")
		g.AddEdge("qux", "foo")
		g.AddNode("qax")

		sorted, err := g.Sort()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(sorted) != 5 {
			t.Fatalf("expected 5 nodes, got %d", len(sorted))
		}

		pos := make(map[string]int)
		for i, v := range sorted {
			pos[v] = i
		}

		if pos["foo"] > pos["bar"] {
			t.Errorf("expected foo to come before bar")
		}
		if pos["foo"] > pos["qux"] {
			t.Errorf("expected foo to come before qux")
		}
		if pos["bar"] > pos["baz"] {
			t.Errorf("expected bar to come before baz")
		}
	})

	t.Run("Cycle Detection", func(t *testing.T) {
		t.Parallel()
		g := graph.New[string]()
		g.AddEdge("foo", "bar")
		g.AddEdge("bar", "baz")
		g.AddEdge("baz", "foo")

		_, err := g.Sort()
		if !errors.Is(err, graph.ErrCycleDetected) {
			t.Fatalf("expected cycle detection error, got %v", err)
		}
	})
}
