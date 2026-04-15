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

package di_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deep-rent/nexus/di"
)

type (
	mockServiceA struct{ ID int }
	mockServiceB struct{ DepA mockServiceA }
	mockServiceC struct{ ID int }
	mockServiceD struct{ DepB mockServiceB }
	mockServiceE struct{ DepC *mockServiceC }
	mockServiceF struct{}
	mockServiceX struct{ DepY *mockServiceY }
	mockServiceY struct{ DepX mockServiceX }
	I            interface{ Work() }
	mockI        struct{ done atomic.Bool }
)

func (c *mockI) Work() { c.done.Store(true) }

var _ I = (*mockI)(nil)

var (
	mockSlotA = di.NewSlot[mockServiceA]("service", "a")
	mockSlotB = di.NewSlot[mockServiceB]("service", "b")
	mockSlotC = di.NewSlot[*mockServiceC]("service", "c")
	mockSlotD = di.NewSlot[mockServiceD]("service", "d")
	mockSlotE = di.NewSlot[mockServiceE]("service", "e")
	mockSlotF = di.NewSlot[*mockServiceF]("service", "f")
	mockSlotI = di.NewSlot[I]("service", "i")
	mockSlotX = di.NewSlot[mockServiceX]("cycle", "x")
	mockSlotY = di.NewSlot[*mockServiceY]("cycle", "y")

	errPanicSentinel = errors.New("provider panicked with error")
)

func mockProvideA(_ di.Container) (mockServiceA, error) {
	return mockServiceA{ID: 1}, nil
}

func mockProvideB(c di.Container) (mockServiceB, error) {
	a := di.Required(c, mockSlotA)
	return mockServiceB{DepA: a}, nil
}

func mockProvideC(_ di.Container) (*mockServiceC, error) {
	return &mockServiceC{ID: 3}, nil
}

func mockProvideD(c di.Container) (mockServiceD, error) {
	b := di.Required(c, mockSlotB)
	return mockServiceD{DepB: b}, nil
}

func mockProvideE(c di.Container) (mockServiceE, error) {
	cInst := di.Optional(c, mockSlotC)
	return mockServiceE{DepC: cInst}, nil
}

func mockProvideX(c di.Container) (mockServiceX, error) {
	y := di.Required(c, mockSlotY)
	return mockServiceX{DepY: y}, nil
}

func mockProvideY(c di.Container) (*mockServiceY, error) {
	x := di.Required(c, mockSlotX)
	return &mockServiceY{DepX: x}, nil
}

func mockProvideNil(_ di.Container) (*mockServiceF, error) {
	return nil, nil
}

func mockProvideError(_ di.Container) (mockServiceA, error) {
	return mockServiceA{}, errors.New("provider failed")
}

func mockProvidePanicString(_ di.Container) (mockServiceA, error) {
	panic("provider panicked with string")
}

func mockProvidePanicError(_ di.Container) (mockServiceA, error) {
	panic(errPanicSentinel)
}

func mockProvideI(_ di.Container) (I, error) {
	return &mockI{}, nil
}

func TestBinding(t *testing.T) {
	t.Parallel()

	t.Run("new injector with context", func(t *testing.T) {
		t.Parallel()
		type key string
		ctx := context.WithValue(t.Context(), key("id"), "test1")
		in := di.NewInjector(di.WithContext(ctx))
		if in == nil {
			t.Fatal("NewInjector() = nil; want non-nil")
		}
		if got, want := in.Context().Value(key("id")), "test1"; got != want {
			t.Errorf("Value(%q) = %v; want %v", "id", got, want)
		}
	})

	t.Run("bind panics on duplicate slot", func(t *testing.T) {
		t.Parallel()
		in := di.NewInjector()
		di.Bind(in, mockSlotA, mockProvideA, di.Transient())
		defer func() {
			if recover() == nil {
				t.Error("Bind() did not panic on duplicate slot")
			}
		}()
		di.Bind(in, mockSlotA, mockProvideA, di.Transient())
	})

	t.Run("override replaces existing binding", func(t *testing.T) {
		t.Parallel()
		in := di.NewInjector()
		di.Bind(in, mockSlotA, mockProvideA, di.Transient())

		di.Override(in, mockSlotA, func(_ di.Container) (mockServiceA, error) {
			return mockServiceA{ID: 99}, nil
		}, di.Transient())

		instance, err := di.Use(in, mockSlotA)
		if err != nil {
			t.Fatalf("Use() unexpected error: %v", err)
		}
		if got, want := instance.ID, 99; got != want {
			t.Errorf("ID = %d; want %d", got, want)
		}
	})
}

func TestResolution(t *testing.T) {
	t.Parallel()

	t.Run("transient", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int32
		provider := func(_ di.Container) (mockServiceA, error) {
			calls.Add(1)
			return mockServiceA{}, nil
		}

		in := di.NewInjector()
		di.Bind(in, mockSlotA, provider, di.Transient())

		_, err := di.Use(in, mockSlotA)
		if err != nil {
			t.Fatalf("Use() unexpected error: %v", err)
		}
		_, err = di.Use(in, mockSlotA)
		if err != nil {
			t.Fatalf("Use() unexpected error: %v", err)
		}

		if got, want := calls.Load(), int32(2); got != want {
			t.Errorf("calls = %d; want %d", got, want)
		}
	})

	t.Run("singleton", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int32
		slotAPtr := di.NewSlot[*mockServiceA]("service", "a-ptr")
		provider := func(_ di.Container) (*mockServiceA, error) {
			calls.Add(1)
			return &mockServiceA{}, nil
		}

		in := di.NewInjector()
		di.Bind(in, slotAPtr, provider, di.Singleton())

		a1, err := di.Use(in, slotAPtr)
		if err != nil {
			t.Fatalf("Use() unexpected error: %v", err)
		}
		a2, err := di.Use(in, slotAPtr)
		if err != nil {
			t.Fatalf("Use() unexpected error: %v", err)
		}

		if got, want := calls.Load(), int32(1); got != want {
			t.Errorf("calls = %d; want %d", got, want)
		}
		if a1 != a2 {
			t.Errorf("Use() instances differ; want same")
		}
	})

	t.Run("singleton concurrent access", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int32
		provider := func(_ di.Container) (mockServiceA, error) {
			time.Sleep(10 * time.Millisecond)
			calls.Add(1)
			return mockServiceA{ID: 123}, nil
		}

		in := di.NewInjector()
		di.Bind(in, mockSlotA, provider, di.Singleton())

		var wg sync.WaitGroup
		for range 100 {
			wg.Go(func() {
				instance, err := di.Use(in, mockSlotA)
				if err != nil {
					t.Errorf("Use() unexpected error: %v", err)
					return
				}
				if instance.ID != 123 {
					t.Errorf("ID = %d; want 123", instance.ID)
				}
			})
		}
		wg.Wait()

		if got, want := calls.Load(), int32(1); got != want {
			t.Errorf("calls = %d; want %d", got, want)
		}
	})

	t.Run("scoped", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int32
		slot := di.NewSlot[*mockServiceA]("service", "a-ptr")
		provider := func(_ di.Container) (*mockServiceA, error) {
			calls.Add(1)
			return &mockServiceA{}, nil
		}

		ctx1 := di.NewScope(t.Context())
		ctx2 := di.NewScope(t.Context())

		in1 := di.NewInjector(di.WithContext(ctx1))
		di.Bind(in1, slot, provider, di.Scoped())
		s1a1 := di.Required(in1, slot)
		s1a2 := di.Required(in1, slot)

		if s1a1 != s1a2 {
			t.Error("instances in same scope differ; want same")
		}

		in2 := di.NewInjector(di.WithContext(ctx2))
		di.Bind(in2, slot, provider, di.Scoped())
		s2a1 := di.Required(in2, slot)

		if s1a1 == s2a1 {
			t.Error("instances across scopes are same; want different")
		}
		if got, want := calls.Load(), int32(2); got != want {
			t.Errorf("calls = %d; want %d", got, want)
		}
	})

	t.Run("scoped fails without scope", func(t *testing.T) {
		t.Parallel()
		in := di.NewInjector()
		di.Bind(in, mockSlotA, mockProvideA, di.Scoped())
		_, err := di.Use(in, mockSlotA)
		if err == nil {
			t.Fatal("Use() expected error for missing scope, got nil")
		}
		if got, want := err.Error(),
			"no scope cache found in context"; !strings.Contains(got, want) {
			t.Errorf("error = %q; want to contain %q", got, want)
		}
	})
}

func TestInjection(t *testing.T) {
	t.Parallel()

	t.Run("full dependency graph", func(t *testing.T) {
		t.Parallel()
		in := di.NewInjector()
		di.Bind(in, mockSlotA, mockProvideA, di.Singleton())
		di.Bind(in, mockSlotB, mockProvideB, di.Singleton())
		di.Bind(in, mockSlotC, mockProvideC, di.Singleton())
		di.Bind(in, mockSlotD, mockProvideD, di.Singleton())
		di.Bind(in, mockSlotE, mockProvideE, di.Singleton())

		d, err := di.Use(in, mockSlotD)
		if err != nil {
			t.Fatalf("Use(SlotD) error: %v", err)
		}
		if got, want := d.DepB.DepA.ID, 1; got != want {
			t.Errorf("ID = %d; want %d", got, want)
		}

		e, err := di.Use(in, mockSlotE)
		if err != nil {
			t.Fatalf("Use(SlotE) error: %v", err)
		}
		if e.DepC == nil {
			t.Fatal("DepC is nil; want non-nil")
		}
		if got, want := e.DepC.ID, 3; got != want {
			t.Errorf("DepC.ID = %d; want %d", got, want)
		}
	})

	t.Run("use returns error for unbound slot", func(t *testing.T) {
		t.Parallel()
		in := di.NewInjector()
		_, err := di.Use(in, mockSlotA)
		if err == nil {
			t.Fatal("Use() expected error for unbound slot, got nil")
		}
		if !errors.Is(err, di.ErrUnbound) {
			t.Errorf("error expected to wrap ErrUnbound, got: %v", err)
		}
	})

	t.Run("use returns error from provider", func(t *testing.T) {
		t.Parallel()
		in := di.NewInjector()
		di.Bind(in, mockSlotA, mockProvideError, di.Transient())

		_, err := di.Use(in, mockSlotA)
		if err == nil {
			t.Fatal("Use() expected provider error, got nil")
		}
		if got, want := err.Error(), "provider failed"; got != want {
			t.Errorf("error = %q; want %q", got, want)
		}
	})

	t.Run("use recovers from provider panic with string", func(t *testing.T) {
		t.Parallel()
		in := di.NewInjector()
		di.Bind(in, mockSlotA, mockProvidePanicString, di.Transient())

		_, err := di.Use(in, mockSlotA)
		if err == nil {
			t.Fatal("Use() expected recovery error from panic, got nil")
		}
		if got, want := err.Error(),
			"panic during provider call"; !strings.Contains(got, want) {
			t.Errorf("error = %q; want to contain %q", got, want)
		}
		if got, want := err.Error(),
			"provider panicked with string"; !strings.Contains(got, want) {
			t.Errorf("error = %q; want to contain %q", got, want)
		}
	})

	t.Run("use recovers from panic with wrapped error", func(t *testing.T) {
		t.Parallel()
		in := di.NewInjector()
		di.Bind(in, mockSlotA, mockProvidePanicError, di.Transient())

		_, err := di.Use(in, mockSlotA)
		if err == nil {
			t.Fatal("Use() expected recovery error from panic, got nil")
		}
		if !errors.Is(err, errPanicSentinel) {
			t.Errorf("error expected to wrap errPanicSentinel, got: %v", err)
		}
	})

	t.Run("optional returns nil without panic", func(t *testing.T) {
		t.Parallel()
		in := di.NewInjector()
		di.Bind(in, mockSlotF, mockProvideNil, di.Transient())

		instance := di.Optional(in, mockSlotF)
		if instance != nil {
			t.Errorf("Optional() = %v; want nil", instance)
		}
	})

	t.Run("required panics on nil value", func(t *testing.T) {
		t.Parallel()
		in := di.NewInjector()
		di.Bind(in, mockSlotF, mockProvideNil, di.Transient())

		defer func() {
			if recover() == nil {
				t.Error("Required() did not panic on nil value")
			}
		}()

		di.Required(in, mockSlotF)
	})

	t.Run("required does not panic on non-nil value", func(t *testing.T) {
		t.Parallel()
		in := di.NewInjector()
		di.Bind(in, mockSlotC, mockProvideC, di.Transient())

		c := di.Required(in, mockSlotC)
		if c == nil {
			t.Error("Required() = nil; want non-nil")
		}
	})

	t.Run("interface binding", func(t *testing.T) {
		t.Parallel()
		in := di.NewInjector()
		di.Bind(in, mockSlotI, mockProvideI, di.Singleton())

		instance, err := di.Use(in, mockSlotI)
		if err != nil {
			t.Fatalf("Use() unexpected error: %v", err)
		}
		if instance == nil {
			t.Fatal("Use() = nil; want non-nil")
		}
		instance.Work()

		c, ok := instance.(*mockI)
		if !ok {
			t.Fatalf("instance is %T; want *mockI", instance)
		}
		if !c.done.Load() {
			t.Error("done = false; want true")
		}
	})
}

func TestCircularDependency(t *testing.T) {
	t.Parallel()
	in := di.NewInjector()
	di.Bind(in, mockSlotX, mockProvideX, di.Transient())
	di.Bind(in, mockSlotY, mockProvideY, di.Transient())

	_, err := di.Use(in, mockSlotX)
	if err == nil {
		t.Fatal("Use() expected error for circular dependency, got nil")
	}
	if !errors.Is(err, di.ErrCycle) {
		t.Errorf("error expected to wrap ErrCycle, got: %v", err)
	}
	if got, want := err.Error(), di.Tag(mockSlotX); !strings.Contains(got, want) {
		t.Errorf("error = %q; want to contain %q", got, want)
	}
}
