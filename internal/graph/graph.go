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

// Package graph provides a generic directed acyclic graph (DAG) implementation.
//
// It is used to determine topological orderings of elements, making it ideal
// for resolving dependency trees. The ordering is canonical: among all valid
// topological orders, [Graph.Sort] always yields the one that lists
// unconstrained nodes in their natural order, independent of insertion order.
//
// # Usage
//
// Create a new graph and populate it with nodes and dependency edges.
//
// Example:
//
//	g := graph.New[string]()
//	g.AddEdge("foo", "bar") // foo depends on bar
//	g.AddNode("baz")        // baz is a standalone node
//
//	sorted, err := g.Sort()
//	if err != nil {
//		// Handle cycle detection error
//	}
//	// sorted: []string{"bar", "baz", "foo"}
package graph

import (
	"cmp"
	"errors"
	"slices"
)

// ErrCycleDetected is returned when a cyclic dependency prevents a valid
// sorting of a [Graph].
var ErrCycleDetected = errors.New("cycle detected in dependency graph")

// Graph represents a directed acyclic graph (DAG).
// It is used to determine the correct topological order for processing
// dependencies.
type Graph[T cmp.Ordered] struct {
	nodes  map[T]struct{}
	edges  map[T][]T
	degree map[T]int
}

// New initializes an empty directed acyclic graph.
func New[T cmp.Ordered]() *Graph[T] {
	return &Graph[T]{
		nodes:  make(map[T]struct{}),
		edges:  make(map[T][]T),
		degree: make(map[T]int),
	}
}

// AddNode registers a node in the graph (idempotent).
func (g *Graph[T]) AddNode(v T) {
	if _, exists := g.nodes[v]; !exists {
		g.nodes[v] = struct{}{}
		g.degree[v] = 0
	}
}

// AddEdge registers a dependency where `child` depends on `parent`.
// This guarantees that in the topologically sorted output, `parent` will
// strictly precede `child`. It implicitly adds both the child and parent nodes
// if they do not already exist.
func (g *Graph[T]) AddEdge(child, parent T) {
	g.AddNode(child)
	g.AddNode(parent)

	g.edges[parent] = append(g.edges[parent], child)
	g.degree[child]++
}

// Sort resolves the dependency graph and returns the nodes in canonical
// topological order: parents strictly precede their children, and nodes not
// constrained relative to each other appear in their natural order. The
// result is therefore a pure function of the graph's nodes and edges. It
// returns [ErrCycleDetected] if a cyclic dependency prevents a valid
// sorting.
func (g *Graph[T]) Sort() ([]T, error) {
	var zero []T

	deg := make(map[T]int, len(g.degree))
	for v, d := range g.degree {
		deg[v] = d
		if d == 0 {
			zero = append(zero, v)
		}
	}
	slices.Sort(zero)

	var sorted []T
	for len(zero) > 0 {
		// Pop the smallest node with 0 in-degree.
		curr := zero[0]
		zero = zero[1:]

		// Append the node to the sorted list. Since the graph maps parents
		// to children, roots are processed first.
		sorted = append(sorted, curr)

		// For each child depending on the resolved parent, reduce its
		// in-degree; nodes becoming available are merged into the queue at
		// their sorted position to keep the order canonical.
		for _, child := range g.edges[curr] {
			deg[child]--
			if deg[child] == 0 {
				at, _ := slices.BinarySearch(zero, child)
				zero = slices.Insert(zero, at, child)
			}
		}
	}

	if len(sorted) != len(g.nodes) {
		return nil, ErrCycleDetected
	}

	return sorted, nil
}
