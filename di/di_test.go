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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deep-rent/nexus/di"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ServiceA struct{ ID int }
type ServiceB struct{ DepA ServiceA }
type ServiceC struct{ ID int }
type ServiceD struct{ DepB ServiceB }
type ServiceE struct{ DepC *ServiceC }
type ServiceF struct{}
type ServiceX struct{ DepY *ServiceY }
type ServiceY struct{ DepX ServiceX }
type I interface{ Work() }
type serviceI struct{ done atomic.Bool }

func (c *serviceI) Work() { c.done.Store(true) }

var (
	SlotA = di.NewSlot[ServiceA]("service", "a")
	SlotB = di.NewSlot[ServiceB]("service", "b")
	SlotC = di.NewSlot[*ServiceC]("service", "c")
	SlotD = di.NewSlot[ServiceD]("service", "d")
	SlotE = di.NewSlot[ServiceE]("service", "e")
	SlotF = di.NewSlot[*ServiceF]("service", "f")
	SlotI = di.NewSlot[I]("service", "i")
	SlotX = di.NewSlot[ServiceX]("cycle", "x")
	SlotY = di.NewSlot[*ServiceY]("cycle", "y")
)

func ProvideA(in *di.Injector) (ServiceA, error) {
	return ServiceA{ID: 1}, nil
}

func ProvideB(in *di.Injector) (ServiceB, error) {
	a := di.Required(in, SlotA)
	return ServiceB{DepA: a}, nil
}

func ProvideC(in *di.Injector) (*ServiceC, error) {
	return &ServiceC{ID: 3}, nil
}

func ProvideD(in *di.Injector) (ServiceD, error) {
	b := di.Required(in, SlotB)
	return ServiceD{DepB: b}, nil
}

func ProvideE(in *di.Injector) (ServiceE, error) {
	c := di.Optional(in, SlotC)
	return ServiceE{DepC: c}, nil
}

func ProvideX(in *di.Injector) (ServiceX, error) {
	y := di.Required(in, SlotY)
	return ServiceX{DepY: y}, nil
}

func ProvideY(in *di.Injector) (*ServiceY, error) {
	x := di.Required(in, SlotX)
	return &ServiceY{DepX: x}, nil
}

func ProvideNil(in *di.Injector) (*ServiceF, error) {
	return nil, nil
}

func ProvideError(in *di.Injector) (ServiceA, error) {
	return ServiceA{}, errors.New("provider failed")
}

func ProvidePanic(in *di.Injector) (ServiceA, error) {
	panic("provider panicked")
}

func ProvideI(in *di.Injector) (I, error) {
	return &serviceI{}, nil
}

func TestInjector_Basics(t *testing.T) {
	t.Run("NewInjector with context", func(t *testing.T) {
		type key string
		ctx := context.WithValue(context.Background(), key("id"), "test1")
		in := di.NewInjector(di.WithContext(ctx))
		require.NotNil(t, in)
		assert.Equal(t, "test1", in.Context().Value(key("id")))
	})

	t.Run("Bind panics on duplicate slot", func(t *testing.T) {
		in := di.NewInjector()
		di.Bind(in, SlotA, ProvideA, di.Transient())
		assert.Panics(t, func() {
			di.Bind(in, SlotA, ProvideA, di.Transient())
		})
	})

	t.Run("Override replaces existing binding", func(t *testing.T) {
		in := di.NewInjector()
		di.Bind(in, SlotA, ProvideA, di.Transient())
		di.Override(in, SlotA, func(in *di.Injector) (ServiceA, error) {
			return ServiceA{ID: 99}, nil
		}, di.Transient())

		instance, err := di.Use(in, SlotA)
		require.NoError(t, err)
		assert.Equal(t, 99, instance.ID)
	})
}

func TestResolvers(t *testing.T) {
	t.Run("Transient", func(t *testing.T) {
		var calls int32
		provider := func(in *di.Injector) (ServiceA, error) {
			atomic.AddInt32(&calls, 1)
			return ServiceA{}, nil
		}

		in := di.NewInjector()
		di.Bind(in, SlotA, provider, di.Transient())

		_, err := di.Use(in, SlotA)
		require.NoError(t, err)
		_, err = di.Use(in, SlotA)
		require.NoError(t, err)

		assert.EqualValues(t, 2, calls, "provider should be invoked twice")

		a1 := di.Required(in, SlotA)
		a2 := di.Required(in, SlotA)
		assert.NotSame(t, &a1, &a2, "should return new instances")
	})

	t.Run("Singleton", func(t *testing.T) {
		var calls int32
		SlotAPtr := di.NewSlot[*ServiceA]("service", "a-ptr")
		provider := func(in *di.Injector) (*ServiceA, error) {
			atomic.AddInt32(&calls, 1)
			return &ServiceA{}, nil
		}

		in := di.NewInjector()
		di.Bind(in, SlotAPtr, provider, di.Singleton())

		_, err := di.Use(in, SlotAPtr)
		require.NoError(t, err)

		_, err = di.Use(in, SlotAPtr)
		require.NoError(t, err)

		assert.EqualValues(t, 1, calls, "provider should be called only once")

		a1 := di.Required(in, SlotAPtr)
		a2 := di.Required(in, SlotAPtr)
		assert.Same(t, a1, a2, "should return the same instance")
	})

	t.Run("Singleton concurrent access", func(t *testing.T) {
		var calls int32
		provider := func(in *di.Injector) (ServiceA, error) {
			time.Sleep(10 * time.Millisecond)
			atomic.AddInt32(&calls, 1)
			return ServiceA{ID: 123}, nil
		}

		in := di.NewInjector()
		di.Bind(in, SlotA, provider, di.Singleton())

		var wg sync.WaitGroup
		for range 100 {
			wg.Go(func() {
				instance, err := di.Use(in, SlotA)
				require.NoError(t, err)
				assert.Equal(t, 123, instance.ID)
			})
		}
		wg.Wait()

		assert.EqualValues(t, 1, calls, "provider should be called only once")
	})

	t.Run("Scoped", func(t *testing.T) {
		var calls int32
		SlotAPtr := di.NewSlot[*ServiceA]("service", "a-ptr")
		provider := func(in *di.Injector) (*ServiceA, error) {
			atomic.AddInt32(&calls, 1)
			return &ServiceA{}, nil
		}

		ctx1 := di.NewScope(t.Context())
		ctx2 := di.NewScope(t.Context())

		in1 := di.NewInjector(di.WithContext(ctx1))
		di.Bind(in1, SlotAPtr, provider, di.Scoped())
		s1_a1 := di.Required(in1, SlotAPtr)
		s1_a2 := di.Required(in1, SlotAPtr)

		assert.Same(t, s1_a1, s1_a2, "should be same instance within same scope")

		in2 := di.NewInjector(di.WithContext(ctx2))
		di.Bind(in2, SlotAPtr, provider, di.Scoped())
		s2_a1 := di.Required(in2, SlotAPtr)

		assert.NotSame(t, s1_a1, s2_a1, "should be different instances")
		assert.EqualValues(t, 2, calls, "provider should be called once per scope")
	})

	t.Run("Scoped fails without scope", func(t *testing.T) {
		in := di.NewInjector()
		di.Bind(in, SlotA, ProvideA, di.Scoped())
		_, err := di.Use(in, SlotA)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no scope cache found in context")
	})
}

func TestResolution(t *testing.T) {
	t.Run("Full dependency graph", func(t *testing.T) {
		in := di.NewInjector()
		di.Bind(in, SlotA, ProvideA, di.Singleton())
		di.Bind(in, SlotB, ProvideB, di.Singleton())
		di.Bind(in, SlotC, ProvideC, di.Singleton())
		di.Bind(in, SlotD, ProvideD, di.Singleton())
		di.Bind(in, SlotE, ProvideE, di.Singleton())

		d, err := di.Use(in, SlotD)
		require.NoError(t, err)
		assert.Equal(t, 1, d.DepB.DepA.ID)

		e, err := di.Use(in, SlotE)
		require.NoError(t, err)
		require.NotNil(t, e.DepC)
		assert.Equal(t, 3, e.DepC.ID)
	})

	t.Run("Use returns error for unbound slot", func(t *testing.T) {
		in := di.NewInjector()
		_, err := di.Use(in, SlotA)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no provider bound for slot")
	})

	t.Run("Use returns error from provider", func(t *testing.T) {
		in := di.NewInjector()
		di.Bind(in, SlotA, ProvideError, di.Transient())
		_, err := di.Use(in, SlotA)
		require.Error(t, err)
		assert.EqualError(t, err, "provider failed")
	})

	t.Run("Use recovers from provider panic", func(t *testing.T) {
		in := di.NewInjector()
		di.Bind(in, SlotA, ProvidePanic, di.Transient())
		_, err := di.Use(in, SlotA)
		require.Error(t, err, "provider panic should be recovered")
		if err != nil {
			assert.Contains(t, err.Error(), "panic during provider call")
			assert.Contains(t, err.Error(), "provider panicked")
		}
	})

	t.Run("Optional returns nil without panic", func(t *testing.T) {
		in := di.NewInjector()
		di.Bind(in, SlotF, ProvideNil, di.Transient())
		instance := di.Optional(in, SlotF)
		assert.Nil(t, instance)
	})

	t.Run("Required panics on nil value", func(t *testing.T) {
		in := di.NewInjector()
		di.Bind(in, SlotF, ProvideNil, di.Transient())
		assert.Panics(t, func() {
			di.Required(in, SlotF)
		})
	})

	t.Run("Required does not panic on non-nil value", func(t *testing.T) {
		in := di.NewInjector()
		di.Bind(in, SlotC, ProvideC, di.Transient())
		assert.NotPanics(t, func() {
			c := di.Required(in, SlotC)
			assert.NotNil(t, c)
		})
	})

	t.Run("Interface binding", func(t *testing.T) {
		in := di.NewInjector()
		di.Bind(in, SlotI, ProvideI, di.Singleton())
		instance, err := di.Use(in, SlotI)
		require.NoError(t, err)
		require.NotNil(t, instance)
		instance.Work()

		c, ok := instance.(*serviceI)
		require.True(t, ok)
		assert.True(t, c.done.Load())
	})
}

func TestCircularDependency(t *testing.T) {
	in := di.NewInjector()
	di.Bind(in, SlotX, ProvideX, di.Transient())
	di.Bind(in, SlotY, ProvideY, di.Transient())

	_, err := di.Use(in, SlotX)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "circular dependency detected")
	assert.Contains(t, err.Error(), di.Tag(SlotX))
}

// func TestTag(t *testing.T) {
// 	t.Cleanup(di.Reset)

// 	t.Run("Unnamed", func(t *testing.T) {
// 		slot := di.NewSlot[string]()
// 		assert.Equal(t, "@string", di.Tag(slot))
// 	})

// 	t.Run("Named", func(t *testing.T) {
// 		slot := di.NewSlot[int]("a", "b", "c")
// 		assert.Equal(t, "a.b.c@int", di.Tag(slot))
// 	})

// 	t.Run("Unknown", func(t *testing.T) {
// 		var slot di.Slot[bool] = new(struct{})
// 		assert.Equal(t, fmt.Sprintf("%p", slot), di.Tag(slot))
// 	})
// }
