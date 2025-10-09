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

// NewSlot creates a new, unique Slot for a given type T. The optional
// keys are used to create a descriptive name for debugging and error messages.
// Multiple keys are joined with dots. This is useful to group related
// services, e.g., by package or feature.
func NewSlot[T any](keys ...string) Slot[T] {
	s := new(struct{})
	tag := "@" + reflect.TypeOf((*T)(nil)).Elem().String()
	if len(keys) != 0 {
		tag = strings.Join(keys, ".") + tag
	}
	slots.Store(s, tag)
	return s
}

var slots = &sync.Map{}

// Tag returns the pre-formatted debug string for a slot.
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

// binding holds the provider and its associated resolution strategy.
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

// WithContext sets the application context for the Injector.
func WithContext(ctx context.Context) Option {
	return func(cfg *config) {
		if ctx != nil {
			cfg.ctx = ctx
		}
	}
}

// Injector is the main dependency injection container.
// It holds all service bindings and manages their singleton instances.
// An Injector is safe for concurrent use.
type Injector struct {
	ctx      context.Context
	bindings map[any]*binding
	mu       sync.RWMutex
}

// NewInjector creates and returns a new, empty Injector with given options.
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
// This context is passed in during the injector's creation via the WithContext
// option. It serves two primary purposes:
//
// 1. It allows for the propagation of request-scoped values, deadlines, and
// cancellation signals throughout the dependency graph. Providers can access
// this context by resolving the injector and calling this method.
//
// 2. It is the key mechanism for enabling scoped dependencies. Resolvers like
// Scoped() use this context to store a cache of instances that live for the
// duration of the context's lifecycle (e.g., a single HTTP request).
func (in *Injector) Context() context.Context {
	return in.ctx
}

// Bind registers a provider function for a specific service slot.
// It panics the slot is already bound.
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
// method for retrieving dependencies when an error is acceptable.
//
// On the first call, it invokes the registered provider and caches the result.
// Subsequent calls return the cached instance. It returns an error if the
// slot is not bound, the provider returns an error, or the provider panics.
func Use[T any](in *Injector, slot Slot[T]) (T, error) {
	v, err := in.Resolve(slot)
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

// Optional resolves a service and panics if a resolution error occurs,
// but allows the provider to return a nil value without panicking.
// It is useful for dependencies that are truly optional.
func Optional[T any](in *Injector, slot Slot[T]) T {
	v, err := Use(in, slot)
	if err != nil {
		panic(err)
	}
	return v
}

// Required resolves a service and panics if an error occurs OR if the
// resulting value is nil (unlike Optional). This should be used for critical
// dependencies that must be resolved.
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

// Resolve is a non-generic method to resolve a dependency from a slot.
// In most cases, the type-safe Use, Optional, or Required functions should be
// preferred.
func (in *Injector) Resolve(slot any) (any, error) {
	return in.resolve(slot, make(map[any]bool))
}

// resolve is the internal, recursive implementation for dependency resolution.
func (in *Injector) resolve(slot any, visiting map[any]bool) (any, error) {
	if visiting[slot] {
		return nil, fmt.Errorf(
			"circular dependency detected while resolving slot %s",
			Tag(slot),
		)
	}

	visiting[slot] = true
	defer delete(visiting, slot)

	in.mu.RLock()
	b, ok := in.bindings[slot]
	in.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no provider bound for slot %s", Tag(slot))
	}

	return b.resolver.Resolve(in, b.provider, slot)
}

// Resolver defines a strategy for managing a service's lifecycle.
type Resolver interface {
	// Resolve provides an instance of the service.
	Resolve(in *Injector, provider any, slot any) (any, error)
}

type singleton struct {
	instance any
	err      error
	once     sync.Once
}

func (s *singleton) Resolve(in *Injector, provider any, slot any) (any, error) {
	s.once.Do(func() { s.instance, s.err = provide(in, provider, slot) })
	return s.instance, s.err
}

// Singleton returns a Resolver that creates an instance once and reuses it
// thereafter.
func Singleton() Resolver {
	return &singleton{}
}

type transient struct{}

func (transient) Resolve(in *Injector, provider any, slot any) (any, error) {
	return provide(in, provider, slot)
}

func provide(in *Injector, provider any, slot any) (instance any, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf(
				"panic during provider call for slot %s: %v",
				Tag(slot), rec,
			)
			instance = nil
		}
	}()

	val := reflect.ValueOf(provider)
	out := val.Call([]reflect.Value{reflect.ValueOf(in)})
	if out[1].IsNil() {
		instance = out[0].Interface()
	} else {
		err = out[1].Interface().(error)
	}

	return
}

// Transient returns a Resolver that creates a new instance on every call.
func Transient() Resolver {
	return transient{}
}

type scopedCacheKey struct{}

// NewScope creates a new context that carries a cache for scoped dependencies.
// This should be called at the beginning of an operation that defines a scope,
// such as a new HTTP request.
func NewScope(ctx context.Context) context.Context {
	return context.WithValue(ctx, scopedCacheKey{}, &sync.Map{})
}

type scoped struct{}

func (s scoped) Resolve(in *Injector, provider any, slot any) (any, error) {
	val := in.Context().Value(scopedCacheKey{})
	cache, ok := val.(*sync.Map)
	if !ok || cache == nil {
		return nil, fmt.Errorf(
			"no scope cache found in context for scoped slot %s",
			Tag(slot),
		)
	}
	if instance, ok := cache.LoadOrStore(slot, nil); ok && instance != nil {
		return instance, nil
	}
	instance, err := provide(in, provider, slot)
	if err != nil {
		cache.Delete(slot)
		return nil, err
	}
	cache.Store(slot, instance)
	return instance, nil
}

// Scoped returns a Resolver that ties the lifecycle of a service to the
// Injector's context. A new instance is created once per scope.
func Scoped() Resolver {
	return scoped{}
}
