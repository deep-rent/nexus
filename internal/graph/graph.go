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

package graph

import (
	"errors"
)

// ErrCycleDetected is returned when a cyclic dependency prevents a valid
// sorting of a [Graph].
var ErrCycleDetected = errors.New("cycle detected in dependency graph")

// Graph represents a directed acyclic graph (DAG).
// It is used to determine the correct topological order for processing
// dependencies.
type Graph[T comparable] struct {
	nodes  map[T]struct{}
	edges  map[T][]T
	degree map[T]int
}

// New initializes an empty directed acyclic graph.
func New[T comparable]() *Graph[T] {
	return &Graph[T]{
		nodes:  make(map[T]struct{}),
		edges:  make(map[T][]T),
		degree: make(map[T]int),
	}
}

// AddNode registers a node in the graph. Nodes added without edges will be
// returned in the sorted output, but their relative order to disconnected nodes
// is undefined.
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

// Sort resolves the dependency graph and returns the nodes in topological
// order (i.e., parents first, followed by their children). It returns
// [ErrCycleDetected] if a cyclic dependency prevents a valid sorting.
func (g *Graph[T]) Sort() ([]T, error) {
	var zero []T

	deg := make(map[T]int, len(g.degree))
	for v, d := range g.degree {
		deg[v] = d
		if d == 0 {
			zero = append(zero, v)
		}
	}

	var sorted []T
	for len(zero) > 0 {
		// Pop a node with 0 in-degree.
		curr := zero[0]
		zero = zero[1:]

		// Append the node to the sorted list. Since the graph maps parents
		// to children, roots are processed first.
		sorted = append(sorted, curr)

		// For each child depending on the resolved parent, reduce its
		// in-degree.
		for _, child := range g.edges[curr] {
			deg[child]--
			if deg[child] == 0 {
				zero = append(zero, child)
			}
		}
	}

	if len(sorted) != len(g.nodes) {
		return nil, ErrCycleDetected
	}

	return sorted, nil
}
