package graph_test

import (
	"testing"

	"github.com/deep-rent/nexus/internal/graph"
)

func TestGraph_Sort(t *testing.T) {
	t.Run("Valid DAG", func(t *testing.T) {
		g := graph.New[string]()
		
		// meter depends on protocol
		g.AddEdge("meter", "protocol")
		// protocol depends on property
		g.AddEdge("protocol", "property")
		// key depends on property
		g.AddEdge("key", "property")
		// isolated node
		g.AddNode("isolated")

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

		// Valid topological sort should place parents before children.
		if pos["property"] > pos["protocol"] {
			t.Errorf("expected property to come before protocol")
		}
		if pos["property"] > pos["key"] {
			t.Errorf("expected property to come before key")
		}
		if pos["protocol"] > pos["meter"] {
			t.Errorf("expected protocol to come before meter")
		}
	})

	t.Run("Cycle Detection", func(t *testing.T) {
		g := graph.New[string]()
		g.AddEdge("A", "B")
		g.AddEdge("B", "C")
		g.AddEdge("C", "A") // cycle

		_, err := g.Sort()
		if err != graph.ErrCycleDetected {
			t.Fatalf("expected ErrCycleDetected, got %v", err)
		}
	})
}
