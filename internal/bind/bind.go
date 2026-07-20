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

// Package bind provides a reflective struct binding engine for populating
// struct fields from arbitrary key-value data sources.
//
// It serves as the core binding mechanism for configuration packages like env
// and HTTP routing layers. It parses struct tags, supports configurable field
// name transformations, handles primitive and standard library type conversions
// (such as [time.Duration] and [url.URL]), and supports optional reflection
// metadata caching for optimal performance.
//
// # Usage
//
// Create a Binder targeting a specific struct tag namespace and populate target
// structs using a custom or built-in Source implementation.
//
// Example:
//
//	binder := bind.New("form", bind.WithCache(true))
//	err := binder.Bind(&myStruct, "", mySource)
package bind

import (
	"encoding"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sync"
	"time"

	"github.com/deep-rent/nexus/internal/pointer"
	"github.com/deep-rent/nexus/internal/tag"
)

// Source provides values for a given key. It natively supports returning
// multiple values (e.g. for HTTP arrays) to correctly parse slices.
type Source interface {
	Lookup(key string) ([]string, bool)
}

// Transformer is a function that transforms a struct field name into a key.
type Transformer func(string) string

// resolver resolves reflection metadata for a given type.
type resolver interface {
	Resolve(rt reflect.Type) ([]field, error)
}

type defaultResolver struct {
	name      string
	transform Transformer
}

func (r *defaultResolver) Resolve(rt reflect.Type) ([]field, error) {
	fields := make([]field, 0, rt.NumField())
	for i := range rt.NumField() {
		ft := rt.Field(i)

		if !ft.IsExported() {
			continue
		}

		val := ft.Tag.Get(r.name)
		if val == "-" {
			continue
		}

		flags, err := parse(val)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", ft.Name, err)
		}

		f := field{
			Index:  i,
			Name:   ft.Name,
			Key:    flags.Key,
			Flags:  flags,
			Inline: flags.Inline,
		}

		// Inlining merges a field's own keys into the enclosing namespace,
		// which only has meaning for an embedded struct. Silently treating
		// the option as a prefixed nested struct would bind the values under
		// keys the author did not ask for.
		if f.Inline && !ft.Anonymous {
			return nil, fmt.Errorf(
				"field %q: option %q requires an embedded field",
				ft.Name, "inline",
			)
		}

		if f.Key == "" {
			f.Key = r.transform(ft.Name)
		}

		f.Embedded = isEmbedded(ft)

		if f.Inline && !f.Embedded {
			return nil, fmt.Errorf(
				"field %q: option %q requires a struct field",
				ft.Name, "inline",
			)
		}

		fields = append(fields, f)
	}

	return fields, nil
}

type cachingResolver struct {
	cache    sync.Map
	resolver resolver
}

func (r *cachingResolver) Resolve(rt reflect.Type) ([]field, error) {
	if cached, ok := r.cache.Load(rt); ok {
		return cached.([]field), nil
	}
	fields, err := r.resolver.Resolve(rt)
	if err != nil {
		// A rejected type is not cached: the tags cannot change, so the same
		// error is produced again, and caching it would only keep the failure
		// alive in memory.
		return nil, err
	}
	r.cache.Store(rt, fields)
	return fields, nil
}

type config struct {
	transform Transformer
	cache     bool
}

// Option configures a Binder.
type Option func(*config)

// WithTransformer sets the name transformation function.
func WithTransformer(t Transformer) Option {
	return func(c *config) {
		if t != nil {
			c.transform = t
		}
	}
}

// WithCache enables or disables metadata caching.
func WithCache(enable bool) Option {
	return func(c *config) {
		c.cache = enable
	}
}

// Binder extracts values from a generic key-value source into a struct.
type Binder struct {
	resolver resolver
}

// New creates a new Binder using the specified struct tag for metadata parsing.
func New(name string, opts ...Option) *Binder {
	cfg := &config{
		transform: func(s string) string { return s },
		cache:     false,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	var resolver resolver = &defaultResolver{
		name:      name,
		transform: cfg.transform,
	}
	if cfg.cache {
		resolver = &cachingResolver{
			resolver: resolver,
		}
	}

	return &Binder{
		resolver: resolver,
	}
}

// Bind populates the fields of a struct using the provided source.
// The given value v must be a non-nil pointer to a struct.
func (b *Binder) Bind[T any](v *T, prefix string, source Source) error {
	if v == nil {
		return errors.New(
			"expected a non-nil pointer to a struct",
		)
	}
	val := reflect.ValueOf(v).Elem()
	if kind := val.Kind(); kind != reflect.Struct {
		return fmt.Errorf(
			"expected a pointer to a struct, but got pointer to %v", kind,
		)
	}
	return b.process(val, prefix, source)
}

func (b *Binder) process(rv reflect.Value, prefix string, source Source) error {
	fields, err := b.resolver.Resolve(rv.Type())
	if err != nil {
		return err
	}
	for _, f := range fields {
		fv := rv.Field(f.Index)

		// Inline struct
		if f.Inline {
			embedded := pointer.Deref(fv)
			if err := b.process(embedded, prefix, source); err != nil {
				return err
			}
			continue
		}

		key := f.Key

		// Embedded structured prefix
		if f.Embedded {
			nested := prefix
			if f.Flags.Prefix != nil {
				nested += *f.Flags.Prefix
			} else {
				nested += key + "_"
			}
			embedded := pointer.Deref(fv)
			if err := b.process(embedded, nested, source); err != nil {
				return err
			}
			continue
		}

		// Regular field
		key = prefix + key
		vals, ok := source.Lookup(key)

		// A key reported as present but carrying no values holds nothing to
		// assign, so it is treated as absent rather than indexed into.
		if len(vals) == 0 {
			ok = false
		}

		if !ok {
			switch {
			case f.Flags.Default != "":
				vals = []string{f.Flags.Default}
			case f.Flags.Required:
				return fmt.Errorf("required key %q is missing", key)
			default:
				continue
			}
		}

		if err := setValues(fv, vals, f.Flags); err != nil {
			return fmt.Errorf(
				"could not set field %q from key %q: %w",
				f.Name, key, err,
			)
		}
	}
	return nil
}

type field struct {
	Index    int
	Name     string
	Key      string
	Flags    *Flags
	Inline   bool
	Embedded bool
}

// Flags encapsulates the options parsed from a tag.
type Flags struct {
	Key      string
	Prefix   *string
	Split    string
	Unit     string
	Format   string
	Default  string
	Inline   bool
	Required bool
}

func parse(s string) (*Flags, error) {
	t := tag.Parse(s)
	f := &Flags{Key: t.Name, Split: ","}

	seen := make(map[string]bool)
	for k, v := range t.Opts() {
		if seen[k] {
			return nil, fmt.Errorf("duplicate option: %q", k)
		}
		switch k {
		case "format":
			f.Format = v
		case "prefix":
			f.Prefix = &v
		case "split":
			f.Split = v
		case "unit":
			f.Unit = v
		case "default":
			f.Default = v
		case "inline":
			f.Inline = true
		case "required":
			f.Required = true
		default:
			return nil, fmt.Errorf("unknown option: %q", k)
		}
		seen[k] = true
	}
	return f, nil
}

// isEmbedded checks if a struct field is a true embedded struct that should
// be processed recursively.
func isEmbedded(f reflect.StructField) bool {
	t := f.Type
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return false
	}
	if t == typeTime || t == typeURL || t == typeLocation {
		return false
	}
	if t.Implements(typeTextUnmarshaler) ||
		reflect.PointerTo(t).Implements(typeTextUnmarshaler) {
		return false
	}
	return true
}

var (
	typeTime            = reflect.TypeFor[time.Time]()
	typeDuration        = reflect.TypeFor[time.Duration]()
	typeLocation        = reflect.TypeFor[time.Location]()
	typeURL             = reflect.TypeFor[url.URL]()
	typeTextUnmarshaler = reflect.TypeFor[encoding.TextUnmarshaler]()
)
