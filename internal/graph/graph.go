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

var ErrCycleDetected = errors.New("cycle detected in dependency graph")

// Graph represents a directed acyclic graph (DAG).
// It is used to determine the correct topological order for processing
// dependencies.
type Graph[T comparable] struct {
	nodes  map[T]struct{}
	edges  map[T][]T
	degree map[T]int
}

// New initializes an empty graph.
func New[T comparable]() *Graph[T] {
	return &Graph[T]{
		nodes:  make(map[T]struct{}),
		edges:  make(map[T][]T),
		degree: make(map[T]int),
	}
}

// AddNode registers a node in the graph.
func (g *Graph[T]) AddNode(v T) {
	if _, exists := g.nodes[v]; !exists {
		g.nodes[v] = struct{}{}
		g.degree[v] = 0
	}
}

// AddEdge registers a dependency: `child` depends on `parent`.
// It implicitly adds the child and parent nodes if they do not exist.
func (g *Graph[T]) AddEdge(child, parent T) {
	g.AddNode(child)
	g.AddNode(parent)

	g.edges[child] = append(g.edges[child], parent)
	g.degree[parent]++
}

// Sort returns the topological order of entities (parents first, then
// children). It returns an error if a cycle is detected.
func (g *Graph[T]) Sort() ([]T, error) {
	var zero []T

	copy := make(map[T]int, len(g.degree))
	for node, degree := range g.degree {
		copy[node] = degree
		if degree == 0 {
			zero = append(zero, node)
		}
	}

	var sorted []T
	for len(zero) > 0 {
		// Pop a node with 0 in-degree.
		curr := zero[0]
		zero = zero[1:]

		// We append it to the front of the sorted list because Kahn's algorithm
		// on a "child -> parent" edge map naturally produces "children first".
		// By prepending, we get "parents first".
		sorted = append([]T{curr}, sorted...)

		// For each parent that `curr` depends on, reduce its in-degree.
		for _, parent := range g.edges[curr] {
			copy[parent]--
			if copy[parent] == 0 {
				zero = append(zero, parent)
			}
		}
	}

	if len(sorted) != len(g.nodes) {
		return nil, ErrCycleDetected
	}

	return sorted, nil
}
