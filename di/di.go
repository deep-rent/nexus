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

// Package di provides a type-safe, concurrent dependency injection
// container for Go applications.
//
// The core concepts are:
//   - Injector: The main container that holds all service bindings.
//   - Slot: A unique, typed key used to register and retrieve services.
//   - Provider: A factory function that creates an instance of a service.
//   - Resolver: A strategy that defines the lifecycle of a service.
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
//	// Ion represents any particle with a symbol and a charge.
//	type Ion interface {
//	  Symbol() string
//	  Charge() int
//	}
//
//	// Salt is our final product, which depends on two Ions.
//	type Salt struct {
//	  cation Ion
//	  anion  Ion
//	}
//
//	func (s Salt) Formula() string {
//	  return s.cation.Symbol() + s.anion.Symbol()
//	}
//
// Step 2: Create Slots for Roles (The Unique Labels)
//
// The key insight here is that slots distinguish dependencies by their role,
// not just their type. Even though both slots below are for the Ion type,
// they are unique keys. This allows us to inject the right ion into the right
// place. The tags ("ion", "cation", etc.) are optional but help with debugging
// in case something goes wrong.
//
//	var (
//	  SlotCation = di.NewSlot[Ion]("ion", "cation")
//	  SlotAnion  = di.NewSlot[Ion]("ion", "anion")
//	  SlotSalt   = di.NewSlot[Salt]("compound", "salt")
//	)
//
// Step 3: Write Providers (The Recipes)
//
// Providers now return the generic Ion interface. The Salt provider can
// then request two different Ions by using their distinct role-based slots.
//
//	// ProvideSodium provides a concrete Ion to fulfill the Cation role.
//	func ProvideSodium(*di.Injector) (Ion, error) {
//	  type Sodium struct{}
//	  func (na Sodium) Symbol() string { return "Na" }
//	  func (na Sodium) Charge() int    { return 1 }
//	  return Sodium{}, nil
//	}
//
//	// ProvideChloride provides a concrete Ion to fulfill the Anion role.
//	func ProvideChloride(*di.Injector) (Ion, error) {
//	  type Chloride struct{}
//	  func (cl Chloride) Symbol() string { return "Cl" }
//	  func (cl Chloride) Charge() int    { return -1 }
//	  return Chloride{}, nil
//	}
//
//	// ProvideSalt requests dependencies by their role-specific slots.
//	func ProvideSalt(in *di.Injector) (Salt, error) {
//	  // Request the Ion fulfilling the "Cation" role.
//	  cation := di.Required[Ion](in, SlotCation)
//	  // Request the Ion fulfilling the "Anion" role.
//	  anion := di.Required[Ion](in, SlotAnion)
//	  return Salt{cation: cation, anion: anion}, nil
//	}
//
// Step 4: Assemble the Solution (Configure the Injector)
//
// Now, create an Injector and bind the concrete providers to their
// respective role slots. We are telling the container that Sodium will act
// as our Cation and Chloride will act as our Anion.
//
//	// 1. Create the injector.
//	solution := di.NewInjector()
//
//	// 2. Bind concrete providers to their roles. We use Transient scope to
//	// obtain fresh ions each time we form a new salt molecule.
//	di.Bind(solution, SlotCation, ProvideSodium, di.Transient())
//	di.Bind(solution, SlotAnion, ProvideChloride, di.Transient())
//
//	// 3. Bind the provider for the final product. A salt molecule is very
//	// stable, so we treat it as a singleton.
//	di.Bind(solution, SlotSalt, ProvideSalt, di.Singleton())
//
// Step 5: Trigger the Reaction (Resolve the Final Product)
//
// When we ask for the Salt, the injector provides the previously registered
// atoms (dependencies) to the Salt provider to form the final molecule. As
// expected, we obtain ordinary table salt (NaCl).
//
//	// This call triggers the entire dependency chain.
//	salt := di.Required[Salt](solution, SlotSalt)
//
//	fmt.Printf("Successfully formed: %s\n", salt.Formula())
//	// Output: Successfully formed: NaCl
package di

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// Slot is an abstract, typed symbol for an injectable service.
// It is a unique pointer that acts as a map key within the Injector,
// while the generic type T provides compile-time type safety.
type Slot[T any] *struct{}

// slots is a global, concurrent map that stores the debug tag for each slot.
var slots = &sync.Map{}

// func Reset() {
// 	slots = &sync.Map{}
// }

// NewSlot creates a new, unique Slot for a given type T.
//
// The optional keys are used to create a descriptive name for debugging and
// error messages. Multiple keys are joined with dots. This is useful to group
// related services, e.g., by package or feature. The assigned tag can be
// retrieved later using the Tag function.
func NewSlot[T any](keys ...string) Slot[T] {
	s := new(struct{})
	t := reflect.TypeOf((*T)(nil)).Elem().String()
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

// Provider defines the function signature for a service factory.
//
// When a service is requested, its provider is called with an instance of the
// Injector, which it can then use to resolve any of its own dependencies (e.g.,
// by calling Use). How often the provider is called depends on the number of
// injection sites and the resolution strategy used when binding the provider to
// a slot. By convention, provider functions should be named "Provide<Type>".
// The associated call to di.Bind should then be done in a function named
// "Bind<Type>".
type Provider[T any] func(in *Injector) (T, error)

// binding holds a provider and its associated resolution strategy.
type binding struct {
	provider any
	resolver Resolver
}

// config holds configuration options for an Injector.
type config struct {
	ctx context.Context
}

// Option configures an Injector.
type Option func(*config)

// WithContext sets the root context for the Injector. If ctx is nil, the
// background context is used by default.
func WithContext(ctx context.Context) Option {
	return func(cfg *config) {
		if ctx != nil {
			cfg.ctx = ctx
		}
	}
}

// Injector is the main dependency injection container.
// It holds all service bindings and manages their lifecycle. An Injector is
// safe for concurrent reads (e.g., using Use, Required), but is not safe for
// concurrent writes (e.g., using Bind, Override). Bindings should be configured
// once at application startup.
type Injector struct {
	ctx      context.Context
	bindings map[any]*binding
	mu       sync.RWMutex
	parent   *Injector
}

// NewInjector creates and returns a new, empty Injector with the given options.
// If no options are provided, it defaults to using context.Background().
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
//
// This context is provided during the injector's creation via the WithContext
// option. It serves two primary purposes:
//
//  1. Propagation: It allows for the propagation of request-scoped values,
//     deadlines, and cancellation signals throughout the dependency graph.
//
//  2. Scoping: It is the key mechanism for enabling scoped dependencies.
//     Resolvers like Scoped() use this context to cache instances that live
//     for the duration of the context's lifecycle (e.g., an HTTP request).
func (in *Injector) Context() context.Context {
	return in.ctx
}

// Bind registers a provider and its resolver for a specific service slot.
// It is typically called during application initialization.
//
// Bind panics if the slot is already bound in the injector.
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
		provider: provider,
		resolver: resolver,
	}
}

// Use resolves a service from the Injector for a given slot. It is the primary
// method for retrieving dependencies when an error is an expected outcome.
//
// It returns an error if the slot is not bound, if the provider returns an
// error, or if a circular dependency is detected. If the provider returns a
// nil value with no error, Use will return the zero value of T.
//
// Use will panic if the value returned by the provider is not assignable to T,
// which indicates a programming error (e.g., a provider returning an
// incompatible type).
func Use[T any](in *Injector, slot Slot[T]) (T, error) {
	v, err := in.Resolve(slot)
	if err != nil {
		var zero T
		return zero, err
	}
	// If the provider returned a nil interface or pointer with no error.
	if v == nil {
		var zero T
		return zero, nil
	}
	// This type assertion is critical. It ensures that the value returned
	// from the non-generic resolver is of the correct type.
	t, ok := v.(T)
	if ok {
		// This panic indicates a bug in a provider implementation, where it
		// returned a concrete type that does not match the slot's type.
		return t, nil
	}
	panic(fmt.Sprintf("provider returned %T for slot %s", v, Tag(slot)))
}

// Optional resolves a service and panics if any resolution error occurs (e.g.,
// an unbound slot or a provider error). However, unlike Required, it allows the
// provider to return a nil value without panicking. It is useful for
// dependencies that are truly optional.
func Optional[T any](in *Injector, slot Slot[T]) T {
	v, err := Use(in, slot)
	if err != nil {
		panic(err)
	}
	return v
}

// Required resolves a service and panics if an error occurs OR if the resolved
// value is nil. This should be used for critical dependencies that must always
// be present.
//
// It checks for nil-ness on interfaces, pointers, maps, slices, channels, and
// functions.
func Required[T any](in *Injector, slot Slot[T]) T {
	v := Optional(in, slot)
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
// This is primarily useful in testing environments to replace production
// services with mocks.
func Override[T any](
	in *Injector,
	slot Slot[T],
	provider Provider[T],
	resolver Resolver,
) {
	in.mu.Lock()
	defer in.mu.Unlock()

	in.bindings[slot] = &binding{
		provider: provider,
		resolver: resolver,
	}
}

// visitingKey is the context key for the circular dependency detection map.
type visitingKey struct{}

// Resolve is a non-generic method to resolve a dependency from a slot.
// In most cases, the type-safe functions (Use, Optional, Required) should be
// preferred. Resolve is mostly useful for framework integrations that may need
// to work with slots of an unknown type.
func (in *Injector) Resolve(slot any) (any, error) {
	// If this injector is a proxy, it means we are in a nested call to resolve().
	// We must use the parent's resolution logic but with our current context,
	// which carries the visiting map.
	if in.parent != nil {
		// The type assertion is safe because we control proxy creation.
		visiting := in.ctx.Value(visitingKey{}).(map[any]bool)
		return in.parent.resolve(slot, visiting)
	}
	// This is a top-level call, so create a fresh map.
	return in.resolve(slot, make(map[any]bool))
}

// resolve is the internal, recursive implementation for dependency resolution.
// The visiting map tracks the current resolution path to detect cycles.
func (in *Injector) resolve(slot any, visiting map[any]bool) (any, error) {
	if visiting[slot] {
		return nil, fmt.Errorf(
			"circular dependency detected while resolving slot %s",
			Tag(slot),
		)
	}

	visiting[slot] = true
	in.mu.RLock()
	b, ok := in.bindings[slot]
	in.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no provider bound for slot %s", Tag(slot))
	}

	// Delegate to the resolver (e.g., Singleton), passing the visiting map.
	val, err := b.resolver.Resolve(in, b.provider, slot, visiting)
	delete(visiting, slot) // Clean up the map on the way back up the call stack.
	return val, err
}

// Resolver defines a strategy for managing a service's lifecycle.
type Resolver interface {
	// Resolve provides an instance according to the strategy it implements.
	// The visiting map tracks the current resolution path to detect cycles.
	Resolve(
		in *Injector,
		provider any,
		slot any,
		visiting map[any]bool,
	) (any, error)
}

// singleton is a Resolver that caches the service instance.
type singleton struct {
	instance any
	err      error
	once     sync.Once
}

func (s *singleton) Resolve(
	in *Injector,
	provider any,
	slot any,
	visiting map[any]bool,
) (any, error) {
	s.once.Do(func() {
		s.instance, s.err = provide(in, provider, slot, visiting)
	})
	return s.instance, s.err
}

// Singleton returns a Resolver that creates an instance once per injector and
// reuses it for all subsequent requests.
func Singleton() Resolver {
	return &singleton{}
}

// transient is a Resolver that always creates a new service instance.
type transient struct{}

func (transient) Resolve(
	in *Injector,
	provider any,
	slot any,
	visiting map[any]bool,
) (any, error) {
	return provide(in, provider, slot, visiting)
}

// provide is an internal helper that safely invokes a provider function.
// It recovers from panics and creates a proxy injector to propagate the
// circular dependency map.
func provide(
	in *Injector,
	provider any,
	slot any,
	visiting map[any]bool,
) (instance any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf(
				"panic during provider call for slot %s: %v",
				Tag(slot), r,
			)
			instance = nil
		}
	}()

	// Create a proxy injector for the provider call. This proxy carries the
	// visiting map within its context. When the provider calls Use/Required,
	// the proxy's Resolve method is called, which correctly propagates the map.
	proxy := &Injector{
		parent: in,
		ctx:    context.WithValue(in.ctx, visitingKey{}, visiting),
	}

	// Use reflection to call the provider.
	val := reflect.ValueOf(provider)
	out := val.Call([]reflect.Value{reflect.ValueOf(proxy)})

	// The provider signature is func(...) (T, error).
	if out[1].IsNil() {
		instance = out[0].Interface()
	} else {
		err = out[1].Interface().(error)
	}

	return
}

// Transient returns a Resolver that creates a new instance of the service
// every time it is requested.
func Transient() Resolver {
	return transient{}
}

// scopedCacheKey is the context key for the scoped dependency cache.
type scopedCacheKey struct{}

// NewScope creates a new context that carries a cache for scoped dependencies.
// This should be called at the beginning of an operation that defines a scope,
// such as a new HTTP request. The returned context should be passed to a new
// or child injector via WithContext.
func NewScope(ctx context.Context) context.Context {
	return context.WithValue(ctx, scopedCacheKey{}, &sync.Map{})
}

// scoped is a Resolver that ties the service lifecycle to a context scope.
type scoped struct{}

func (s scoped) Resolve(
	in *Injector,
	provider any,
	slot any,
	visiting map[any]bool,
) (any, error) {
	val := in.Context().Value(scopedCacheKey{})
	cache, ok := val.(*sync.Map)
	if !ok || cache == nil {
		return nil, fmt.Errorf(
			"no scope cache found in context for scoped slot %s",
			Tag(slot),
		)
	}
	// Check if an instance already exists in the scope's cache.
	// The nil marker (`struct{}{}``) is used to handle the case where a provider
	// legitimately returns nil, to prevent re-invocation.
	if instance, loaded := cache.Load(slot); loaded {
		return instance, nil
	}

	// If not found, create a new instance.
	instance, err := provide(in, provider, slot, visiting)
	if err != nil {
		// Do not cache the slot if the provider failed.
		return nil, err
	}

	// Store the new instance in the cache.
	actual, _ := cache.LoadOrStore(slot, instance)
	return actual, nil
}

// Scoped returns a Resolver that ties the lifecycle of a service to a
// context.Context. A new instance is created once per scope, defined by a
// call to NewScope. It requires that the injector's context was created
// via NewScope.
func Scoped() Resolver {
	return scoped{}
}
