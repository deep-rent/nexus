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

// Package di provides a type-safe, concurrent dependency injection container
// for Go applications.
//
// The core concepts are:
//   - [Injector]: The main container that holds all service bindings.
//   - [Container]: An interface passed to providers to resolve nested
//     dependencies.
//   - [Slot]: A unique, typed key used to register and retrieve services.
//   - [Provider]: A factory function that creates an instance of a service.
//   - [Resolver]: A strategy that defines the lifecycle of a service.
//
// # Usage
//
// Let's explore how to use this container by modeling a simple chemical
// reaction: forming a Salt. This example shows how to use a single interface
// (Ion) for dependencies that fulfill different roles (Cation and Anion).
//
// Step 1: Define a Reusable Abstraction (The Ion Role)
//
// Instead of separate Cation and Anion interfaces, we can define a single,
// reusable Ion interface. Our Salt struct will now depend on two instances
// of this same interface type.
//
// Example:
//
//	// Ion represents any particle with a symbol and a charge.
//	type Ion interface {
//		Symbol() string
//		Charge() int
//	}
//
//	// Salt is our final product, which depends on two Ions.
//	type Salt struct {
//		cation Ion
//		anion  Ion
//	}
//
//	func (s Salt) Formula() string {
//		return s.cation.Symbol() + s.anion.Symbol()
//	}
//
// Step 2: Create Slots for Roles (The Unique Labels)
//
// The key insight here is that slots distinguish dependencies by their role,
// not just their type. Even though both slots below are for the Ion type,
// they are unique keys. This allows us to inject the right ion into the right
// place. The tags ("ion", "cation", etc.) are optional but help with debugging.
//
// Example:
//
//	var (
//		SlotCation = di.NewSlot[Ion]("ion", "cation")
//		SlotAnion  = di.NewSlot[Ion]("ion", "anion")
//		SlotSalt   = di.NewSlot[Salt]("compound", "salt")
//	)
//
// Step 3: Write Providers (The Recipes)
//
// Providers now return the generic Ion interface. The Salt provider can
// then request two different Ions by using their distinct role-based slots.
//
// Example:
//
//	// ProvideSodium provides a concrete Ion to fulfill the Cation role.
//	func ProvideSodium(c di.Container) (Ion, error) {
//		type Sodium struct{}
//		func (na Sodium) Symbol() string { return "Na" }
//		func (na Sodium) Charge() int    { return 1 }
//		return Sodium{}, nil
//	}
//
//	// ProvideChloride provides a concrete Ion to fulfill the Anion role.
//	func ProvideChloride(c di.Container) (Ion, error) {
//		type Chloride struct{}
//		func (cl Chloride) Symbol() string { return "Cl" }
//		func (cl Chloride) Charge() int    { return -1 }
//		return Chloride{}, nil
//	}
//
//	// ProvideSalt requests dependencies by their role-specific slots.
//	func ProvideSalt(c di.Container) (Salt, error) {
//		// Request the Ion fulfilling the "Cation" role.
//		cation := di.Required[Ion](c, SlotCation)
//		// Request the Ion fulfilling the "Anion" role.
//		anion := di.Required[Ion](c, SlotAnion)
//		return Salt{cation: cation, anion: anion}, nil
//	}
//
// Step 4: Assemble the Solution (Configure the Injector)
//
// Now, create an Injector and bind the concrete providers to their
// respective role slots. We use Transient scope to obtain fresh ions
// each time we form a new salt molecule.
//
// Example:
//
//	// 1. Create the injector.
//	solution := di.NewInjector()
//
//	// 2. Bind concrete providers to their roles.
//	di.Bind(solution, SlotCation, ProvideSodium, di.Transient())
//	di.Bind(solution, SlotAnion, ProvideChloride, di.Transient())
//
//	// 3. Bind the provider for the final product.
//	di.Bind(solution, SlotSalt, ProvideSalt, di.Singleton())
//
// Step 5: Trigger the Reaction (Resolve the Final Product)
//
// When we ask for the Salt, the injector provides the previously registered
// atoms (dependencies) to the Salt provider to form the final molecule.
//
// Example:
//
//	// This call triggers the entire dependency chain.
//	salt := di.Required[Salt](solution, SlotSalt)
//
//	fmt.Printf("Successfully formed: %s\n", salt.Formula())
//	// Output: Successfully formed: NaCl
package di

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// Sentinel errors for standard DI failure modes.
var (
	// ErrCycle indicates that a circular dependency was found.
	ErrCycle = errors.New("circular dependency")
	// ErrUnbound indicates that a slot has no provider bound to it.
	ErrUnbound = errors.New("unbound slot")
)

// Slot is an abstract, typed symbol for an injectable service.
// It is a unique pointer that acts as a map key within the [Injector],
// while the generic type T provides compile-time type safety.
type Slot[T any] *struct {
	// The embedded byte ensures a non-zero size, guaranteeing unique memory
	// addresses.

	_ byte
}

// slots is a global, concurrent map that stores the debug tag for each slot.
var slots = &sync.Map{}

// Reset clears all registered slot tags from the internal global map.
func Reset() {
	slots = &sync.Map{}
}

// NewSlot creates a new, unique [Slot] for a given type T.
//
// The optional keys are used to create a descriptive name for debugging and
// error messages. Multiple keys are joined with dots. This is useful to group
// related services, e.g., by package or feature. The assigned tag can be
// retrieved later using the [Tag] function.
func NewSlot[T any](keys ...string) Slot[T] {
	s := new(struct{ _ byte }) // Unique allocation
	t := reflect.TypeFor[T]().String()
	var tag string
	if len(keys) == 0 {
		// Case 1: Unnamed slot, e.g., @string
		tag = "@" + t
	} else {
		// Case 2: Named slot, e.g., a.b.c@int
		tag = strings.Join(keys, ".") + "@" + t
	}
	slots.Store(s, tag)
	return s
}

// Tag returns the pre-formatted debug string for a slot.
//
// The tag is of the form "name@type", where "name" is the optional name
// assigned during slot creation, and "type" is the Go type of the slot. If no
// name was provided, it returns just the type prefixed with "@". If the slot is
// unknown, it falls back to the pointer address.
func Tag(slot any) string {
	if name, ok := slots.Load(slot); ok {
		return name.(string)
	}
	// Fallback to pointer address for unnamed slots.
	return fmt.Sprintf("%p", slot)
}

// Container represents an interface for resolving dependencies.
// Both the top-level [Injector] and the internal resolution state implement
// this interface.
type Container interface {
	// Context returns the context associated with this resolution container.
	Context() context.Context
	// Resolve performs the lookup for the given slot.
	Resolve(slot any) (any, error)
}

// Provider defines the function signature for a service factory.
//
// When a service is requested, its provider is called with a [Container], which
// it can then use to resolve any of its own dependencies (e.g., by calling Use).
// How often the provider is called depends on the number of injection sites and
// the resolution strategy used when binding the provider to a slot.
type Provider[T any] func(c Container) (T, error)

// binding holds a provider and its associated resolution strategy.
type binding struct {
	// provider is the internal wrapped function that returns any.
	provider func(c Container) (any, error)
	// resolver is the lifecycle strategy for this binding.
	resolver Resolver
}

// config holds configuration options for an [Injector].
type config struct {
	// ctx is the base context for the injector.
	ctx context.Context
}

// Option configures an [Injector].
type Option func(*config)

// WithContext sets the root context for the [Injector]. If ctx is nil, the
// background context is used by default.
func WithContext(ctx context.Context) Option {
	return func(cfg *config) {
		if ctx != nil {
			cfg.ctx = ctx
		}
	}
}

// Injector is the main dependency injection container.
// It holds all service bindings and manages their lifecycle. An [Injector] is
// safe for concurrent reads (e.g., using [Use], [Required]), but is not safe
// for concurrent writes (e.g., using [Bind], [Override]). Bindings should be
// configured once at application startup.
type Injector struct {
	// ctx is the root context for all resolutions.
	ctx context.Context
	// bindings maps slots to their respective provider and resolver.
	bindings map[any]*binding
	// mu protects the bindings map from concurrent access.
	mu sync.RWMutex
}

// NewInjector creates and returns a new, empty [Injector] with the given
// options. If no options are provided, it defaults to using
// [context.Background].
func NewInjector(opts ...Option) *Injector {
	cfg := config{
		ctx: context.Background(),
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &Injector{
		ctx:      cfg.ctx,
		bindings: make(map[any]*binding),
	}
}

// Context returns the injector's context.
func (in *Injector) Context() context.Context {
	return in.ctx
}

// Bind registers a provider and its resolver for a specific service slot.
// It is typically called during application initialization.
func Bind[T any](
	in *Injector,
	slot Slot[T],
	provider Provider[T],
	resolver Resolver,
) {
	in.mu.Lock()
	defer in.mu.Unlock()

	if _, ok := in.bindings[slot]; ok {
		panic(fmt.Sprintf("slot %s is already bound", Tag(slot)))
	}

	in.bindings[slot] = &binding{
		provider: func(c Container) (any, error) { return provider(c) },
		resolver: resolver,
	}
}

// Use resolves a service from the [Container] for a given slot. It is the
// primary method for retrieving dependencies when an error is an expected
// outcome.
func Use[T any](c Container, slot Slot[T]) (T, error) {
	v, err := c.Resolve(slot)
	if err != nil {
		var zero T
		return zero, err
	}
	if v == nil {
		var zero T
		return zero, nil
	}
	t, ok := v.(T)
	if ok {
		return t, nil
	}
	panic(fmt.Sprintf("provider returned %T for slot %s", v, Tag(slot)))
}

// Optional resolves a service and panics if any resolution error occurs.
// However, unlike [Required], it allows the provider to return a nil value
// without panicking. It is useful for dependencies that are truly optional.
func Optional[T any](c Container, slot Slot[T]) T {
	v, err := Use(c, slot)
	if err != nil {
		panic(err)
	}
	return v
}

// Required resolves a service and panics if an error occurs OR if the resolved
// value is nil. This should be used for critical dependencies that must always
// be present.
func Required[T any](c Container, slot Slot[T]) T {
	v := Optional(c, slot)
	val := reflect.ValueOf(v)
	switch val.Kind() {
	case
		reflect.Pointer,
		reflect.Interface,
		reflect.Slice,
		reflect.Map,
		reflect.Chan,
		reflect.Func:
		if val.IsNil() {
			panic(fmt.Sprintf(
				"required dependency for slot %s is nil",
				Tag(slot),
			))
		}
	}
	return v
}

// Override registers a provider for a slot, replacing any existing binding.
func Override[T any](
	in *Injector,
	slot Slot[T],
	provider Provider[T],
	resolver Resolver,
) {
	in.mu.Lock()
	defer in.mu.Unlock()

	in.bindings[slot] = &binding{
		provider: func(c Container) (any, error) { return provider(c) },
		resolver: resolver,
	}
}

// Resolve is a non-generic method to resolve a dependency from a slot.
// In most cases, the type-safe functions ([Use], [Optional], [Required]) should
// be preferred.
func (in *Injector) Resolve(slot any) (any, error) {
	// This is a top-level call, so create a fresh map for cycle detection.
	return in.resolve(slot, make(map[any]bool))
}

// resolve is the internal, recursive implementation for dependency resolution.
func (in *Injector) resolve(slot any, visiting map[any]bool) (any, error) {
	if visiting[slot] {
		return nil, fmt.Errorf(
			"%w detected while resolving slot %s",
			ErrCycle, Tag(slot),
		)
	}

	visiting[slot] = true
	in.mu.RLock()
	b, ok := in.bindings[slot]
	in.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf(
			"%w: no provider bound for slot %s",
			ErrUnbound, Tag(slot),
		)
	}

	val, err := b.resolver.Resolve(in, b.provider, slot, visiting)
	delete(visiting, slot) // Clean up the map on the way back up the call stack.
	return val, err
}

// Resolver defines a strategy for managing a service's lifecycle.
type Resolver interface {
	// Resolve determines how the provider should be invoked and if the result
	// should be cached.
	Resolve(
		in *Injector,
		provider func(c Container) (any, error),
		slot any,
		visiting map[any]bool,
	) (any, error)
}

// singleton is a [Resolver] that caches the service instance.
type singleton struct {
	// instance is the cached value returned by the provider.
	instance any
	// err is the cached error returned by the provider.
	err error
	// once ensures the provider is only called once.
	once sync.Once
}

// Resolve implements [Resolver.Resolve] by caching the provider output.
func (s *singleton) Resolve(
	in *Injector,
	provider func(c Container) (any, error),
	slot any,
	visiting map[any]bool,
) (any, error) {
	s.once.Do(func() {
		s.instance, s.err = provide(in, provider, slot, visiting)
	})
	return s.instance, s.err
}

// Singleton returns a [Resolver] that creates an instance once per injector and
// reuses it for all subsequent requests.
func Singleton() Resolver {
	return &singleton{}
}

// transient is a [Resolver] that always creates a new service instance.
type transient struct{}

// Resolve implements [Resolver.Resolve] by calling the provider every time.
func (transient) Resolve(
	in *Injector,
	provider func(c Container) (any, error),
	slot any,
	visiting map[any]bool,
) (any, error) {
	return provide(in, provider, slot, visiting)
}

// Transient returns a [Resolver] that creates a new instance of the service
// every time it is requested.
func Transient() Resolver {
	return transient{}
}

// resolutionState is a lightweight container passed down during graph
// traversal. It tracks cycles seamlessly without inflating context trees or
// duplicating injectors.
type resolutionState struct {
	// injector is the parent container.
	injector *Injector
	// visiting is the map used for circular dependency detection.
	visiting map[any]bool
}

// Context implements [Container.Context].
func (r *resolutionState) Context() context.Context {
	return r.injector.Context()
}

// Resolve implements [Container.Resolve].
func (r *resolutionState) Resolve(slot any) (any, error) {
	return r.injector.resolve(slot, r.visiting)
}

// statePool minimizes allocations during deep dependency tree resolutions.
var statePool = sync.Pool{
	New: func() any { return &resolutionState{} },
}

// provide is an internal helper that safely invokes a provider function.
// It retrieves a state object to maintain the cycle detection map seamlessly.
func provide(
	in *Injector,
	provider func(c Container) (any, error),
	slot any,
	visiting map[any]bool,
) (instance any, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = fmt.Errorf(
					"panic during provider call for slot %s: %w",
					Tag(slot), e,
				)
			} else {
				err = fmt.Errorf(
					"panic during provider call for slot %s: %v",
					Tag(slot), r,
				)
			}
		}
	}()

	// Grab a reusable state object to track the resolution cycle.
	state := statePool.Get().(*resolutionState)
	state.injector = in
	state.visiting = visiting

	instance, err = provider(state)

	// Clean and return the state to the pool.
	state.injector = nil
	state.visiting = nil
	statePool.Put(state)

	return instance, err
}

// scopedKey is the context key for the scoped dependency cache.
type scopedKey struct{}

// NewScope creates a new context that carries a cache for scoped dependencies.
// This should be called at the beginning of an operation that defines a scope,
// such as a new HTTP request. The returned context should be passed to a new
// or child injector via [WithContext].
func NewScope(ctx context.Context) context.Context {
	return context.WithValue(ctx, scopedKey{}, &sync.Map{})
}

// scopedEntry tracks the lifecycle of a dependency within a specific scope.
type scopedEntry struct {
	// once ensures single execution per scope.
	once sync.Once
	// val is the cached scope instance.
	val any
	// err is the cached scope error.
	err error
}

// scoped is a [Resolver] that ties the service lifecycle to a context scope.
type scoped struct{}

// Resolve implements [Resolver.Resolve] using a context-based cache.
func (s scoped) Resolve(
	in *Injector,
	provider func(c Container) (any, error),
	slot any,
	visiting map[any]bool,
) (any, error) {
	val := in.Context().Value(scopedKey{})
	cache, ok := val.(*sync.Map)
	if !ok || cache == nil {
		return nil, fmt.Errorf(
			"no scope cache found in context for scoped slot %s", Tag(slot),
		)
	}

	// Retrieve or create the synchronization entry
	act, _ := cache.LoadOrStore(slot, &scopedEntry{})
	ent := act.(*scopedEntry)

	// Ensure the provider runs exactly once per scope
	ent.once.Do(func() {
		ent.val, ent.err = provide(in, provider, slot, visiting)
	})

	return ent.val, ent.err
}

// Scoped returns a [Resolver] that ties the lifecycle of a service to a
// [context.Context]. A new instance is created once per scope, defined by a
// call to [NewScope]. It requires that the injector's context was created
// via [NewScope].
func Scoped() Resolver {
	return scoped{}
}
