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

package artifact_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/deep-rent/nexus/sec/iam/artifact"
)

type record struct {
	ID    string
	Value int
}

func newMap() *artifact.Map[string, record] {
	return artifact.NewMap(func(r record) string { return r.ID })
}

func TestMap_CRUD(t *testing.T) {
	t.Parallel()
	m := newMap()

	if _, found, err := m.Get(t.Context(), "a"); err != nil || found {
		t.Fatalf("Get on empty map: found=%t err=%v; want absent", found, err)
	}

	if err := m.Create(t.Context(), record{ID: "a", Value: 1}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if v, found, _ := m.Get(t.Context(), "a"); !found || v.Value != 1 {
		t.Fatalf("Get after Create: found=%t v=%+v", found, v)
	}

	if err := m.Update(t.Context(), record{ID: "a", Value: 2}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if v, _, _ := m.Get(t.Context(), "a"); v.Value != 2 {
		t.Fatalf("Get after Update: v=%+v; want Value 2", v)
	}

	if m.Len() != 1 {
		t.Fatalf("Len = %d; want 1", m.Len())
	}
}

func TestMap_DeleteDecidesWinner(t *testing.T) {
	t.Parallel()
	m := newMap()

	if err := m.Create(t.Context(), record{ID: "a"}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Exactly one of N concurrent deletions may report deleted = true.
	var wins sync.Map
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			deleted, err := m.Delete(t.Context(), "a")
			if err != nil {
				t.Errorf("Delete: %v", err)
			}
			if deleted {
				wins.Store(i, true)
			}
		}()
	}
	wg.Wait()

	count := 0
	wins.Range(func(any, any) bool { count++; return true })
	if count != 1 {
		t.Fatalf("got %d winning deletions; want exactly 1", count)
	}
}

func TestMap_Range(t *testing.T) {
	t.Parallel()
	m := newMap()

	for i, id := range []string{"a", "b", "c"} {
		if err := m.Create(t.Context(), record{ID: id, Value: i}); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	seen := make(map[string]int)
	m.Range(func(id string, v record) bool {
		seen[id] = v.Value
		// Reentrancy: callbacks may call back into the Map.
		_, _, _ = m.Get(t.Context(), id)
		return true
	})
	if len(seen) != 3 {
		t.Fatalf("Range visited %d records; want 3", len(seen))
	}

	// Early exit stops the iteration.
	visits := 0
	m.Range(func(string, record) bool {
		visits++
		return false
	})
	if visits != 1 {
		t.Fatalf("Range visited %d records after false; want 1", visits)
	}
}

func TestMap_Err(t *testing.T) {
	t.Parallel()
	m := newMap()
	boom := errors.New("store down")
	m.Err = boom

	if err := m.Create(t.Context(), record{ID: "a"}); !errors.Is(err, boom) {
		t.Errorf("Create: got %v; want the fault", err)
	}
	if _, _, err := m.Get(t.Context(), "a"); !errors.Is(err, boom) {
		t.Errorf("Get: got %v; want the fault", err)
	}
	if err := m.Update(t.Context(), record{ID: "a"}); !errors.Is(err, boom) {
		t.Errorf("Update: got %v; want the fault", err)
	}
	if _, err := m.Delete(t.Context(), "a"); !errors.Is(err, boom) {
		t.Errorf("Delete: got %v; want the fault", err)
	}
}

func TestNewMap_PanicsWithoutKey(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("NewMap(nil) did not panic")
		}
	}()
	artifact.NewMap[string, record](nil)
}
