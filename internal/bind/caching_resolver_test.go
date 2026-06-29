package bind

import (
	"reflect"
	"testing"
)

type mockResolver struct {
	resolveCount int
}

func (m *mockResolver) Resolve(rt reflect.Type) []field {
	m.resolveCount++
	return []field{{Name: "MockField"}} // Dummy return
}

func TestCachingResolver_Resolve(t *testing.T) {
	t.Parallel()

	mock := &mockResolver{}
	cacher := &cachingResolver{
		resolver: mock,
	}

	type DummyStruct struct {
		Foo string
	}
	rt := reflect.TypeOf(DummyStruct{})

	// First call should increment resolveCount and call underlying resolver
	fields1 := cacher.Resolve(rt)
	if mock.resolveCount != 1 {
		t.Errorf("Expected resolveCount to be 1, got %d", mock.resolveCount)
	}
	if len(fields1) != 1 || fields1[0].Name != "MockField" {
		t.Errorf("Unexpected fields returned on first call")
	}

	// Second call should use cache, resolveCount remains 1
	fields2 := cacher.Resolve(rt)
	if mock.resolveCount != 1 {
		t.Errorf("Expected resolveCount to be 1 after cached call, got %d", mock.resolveCount)
	}
	if len(fields2) != 1 || fields2[0].Name != "MockField" {
		t.Errorf("Unexpected fields returned on second call")
	}
	
	// Different type should trigger another resolve call
	type AnotherStruct struct {
		Bar int
	}
	rt2 := reflect.TypeOf(AnotherStruct{})
	
	_ = cacher.Resolve(rt2)
	if mock.resolveCount != 2 {
		t.Errorf("Expected resolveCount to be 2 for a new type, got %d", mock.resolveCount)
	}
}
