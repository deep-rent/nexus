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
