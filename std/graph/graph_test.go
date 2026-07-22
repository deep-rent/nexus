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
	"slices"
	"testing"

	"github.com/deep-rent/nexus/std/graph"
)

func TestNew(t *testing.T) {
	t.Parallel()

	g := graph.New[int]()
	if g == nil {
		t.Fatal("graph should not be nil")
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
			t.Fatalf("should not have returned an error: %v", err)
		}

		if len(sorted) != 5 {
			t.Fatalf("got %d nodes; want 5", len(sorted))
		}

		pos := make(map[string]int)
		for i, v := range sorted {
			pos[v] = i
		}

		if pos["foo"] > pos["bar"] {
			t.Error("foo should come before bar")
		}
		if pos["foo"] > pos["qux"] {
			t.Error("foo should come before qux")
		}
		if pos["bar"] > pos["baz"] {
			t.Error("bar should come before baz")
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
			t.Fatalf("got error %v; want ErrCycleDetected", err)
		}
	})

	t.Run("Canonical Order", func(t *testing.T) {
		t.Parallel()

		// The same node/edge set built in shuffled insertion orders must
		// always yield the identical canonical order: topological, with
		// unconstrained nodes in natural order.
		builds := []func() *graph.Graph[string]{
			func() *graph.Graph[string] {
				g := graph.New[string]()
				g.AddNode("delta")
				g.AddNode("alpha")
				g.AddEdge("omega", "delta")
				g.AddNode("beta")
				return g
			},
			func() *graph.Graph[string] {
				g := graph.New[string]()
				g.AddNode("beta")
				g.AddEdge("omega", "delta")
				g.AddNode("alpha")
				g.AddNode("delta")
				return g
			},
		}

		want := []string{"alpha", "beta", "delta", "omega"}
		for i, build := range builds {
			got, err := build().Sort()
			if err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}
			if !slices.Equal(got, want) {
				t.Errorf("for build %d: got %v; want %v", i, got, want)
			}
		}
	})
}
