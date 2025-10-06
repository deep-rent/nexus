package di

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// DefaultVersion is the default application version exposed by the Injector
// if none is provided.
const DefaultVersion = "development"

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
// When a service is first requested, its provider is called with an
// instance of the *Injector, which it can then use to resolve any
// of its own dependencies (e.g., by calling Use or Req). The result
// will be stored as a singleton and returned on all subsequent requests
// for the same Slot.
type Provider[T any] func(in *Injector) (T, error)

// binding holds the provider and its associated resolution strategy.
type binding struct {
	provider any
	resolver Resolver
}

// config holds configuration options for an Injector.
type config struct {
	version string
	ctx     context.Context
}

// Option configures an Injector.
type Option func(*config)

// WithVersion sets the application version for the Injector.
func WithVersion(version string) Option {
	return func(cfg *config) {
		if version = strings.TrimSpace(version); version != "" {
			cfg.version = version
		}
	}
}

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
	version  string
	ctx      context.Context
	bindings map[any]*binding
	mu       sync.RWMutex
}

// NewInjector creates and returns a new, empty Injector with given options.
func NewInjector(opts ...Option) *Injector {
	cfg := config{
		version: DefaultVersion,
		ctx:     context.Background(),
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &Injector{
		version:  cfg.version,
		ctx:      cfg.ctx,
		bindings: make(map[any]*binding),
	}
}

// Version returns the application version.
func (in *Injector) Version() string {
	return in.version
}

// Context returns the application context.
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

// Resolve is a non-generic method to resolve a dependency from a slot.
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

// Resolver defines a strategy for resolving service instances.
type Resolver interface {
	// Resolve provides an instance of the service within a scope.
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

func provide(in *Injector, provider any, slot any) (any, error) {
	var instance any
	var err error
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

	return instance, err
}

// Transient returns a Resolver that creates a new instance on every call.
func Transient() Resolver {
	return transient{}
}
