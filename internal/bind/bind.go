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
	"github.com/deep-rent/nexus/internal/snake"
	"github.com/deep-rent/nexus/internal/tag"
)

// Lookup is a function that retrieves a value by its key.
type Lookup func(key string) (string, bool)

// Transformer is a function that transforms a struct field name into a key.
type Transformer func(string) string

// resolver resolves reflection metadata for a given type.
type resolver interface {
	Resolve(rt reflect.Type) []meta
}

type defaultResolver struct {
	binder *Binder
}

func (r *defaultResolver) Resolve(rt reflect.Type) []meta {
	return r.binder.buildMeta(rt)
}

type cachingResolver struct {
	cache    sync.Map
	resolver resolver
}

func (r *cachingResolver) Resolve(rt reflect.Type) []meta {
	if cached, ok := r.cache.Load(rt); ok {
		return cached.([]meta)
	}
	fields := r.resolver.Resolve(rt)
	r.cache.Store(rt, fields)
	return fields
}

// Option configures a Binder.
type Option func(*Binder)

// WithTransformer sets the name transformation function.
func WithTransformer(t Transformer) Option {
	return func(b *Binder) {
		if t != nil {
			b.transform = t
		}
	}
}

// WithCache enables or disables metadata caching.
func WithCache(enable bool) Option {
	return func(b *Binder) {
		b.useCache = enable
	}
}

// Binder extracts values from a generic key-value source into a struct.
type Binder struct {
	name      string
	transform Transformer
	useCache  bool
	resolver  resolver
}

// New creates a new Binder using the specified struct tag for metadata parsing.
func New(name string, opts ...Option) *Binder {
	b := &Binder{
		name:      name,
		transform: snake.ToLower,
		useCache:  true,
	}
	for _, opt := range opts {
		opt(b)
	}

	b.resolver = &defaultResolver{binder: b}
	if b.useCache {
		b.resolver = &cachingResolver{resolver: b.resolver}
	}

	return b
}

// Bind populates the fields of a struct using the provided lookup function.
// The given value v must be a non-nil pointer to a struct.
func (b *Binder) Bind(v any, prefix string, lookup Lookup) error {
	ptr := reflect.ValueOf(v)
	if ptr.Kind() != reflect.Pointer || ptr.IsNil() {
		return errors.New(
			"bind: expected a non-nil pointer to a struct",
		)
	}
	val := ptr.Elem()
	if kind := val.Kind(); kind != reflect.Struct {
		return fmt.Errorf(
			"bind: expected a pointer to a struct, but got pointer to %v", kind,
		)
	}
	return b.process(val, prefix, lookup)
}

func (b *Binder) process(rv reflect.Value, prefix string, lookup Lookup) error {
	fields := b.resolver.Resolve(rv.Type())
	for _, f := range fields {
		if f.Err != nil {
			return f.Err
		}

		fv := rv.Field(f.Index)

		// Inline struct
		if f.Inline {
			embedded := pointer.Deref(fv)
			if err := b.process(embedded, prefix, lookup); err != nil {
				return err
			}
			continue
		}

		key := f.Name

		// Embedded structured prefix
		if f.Embedded {
			nested := prefix
			if f.Flags.Prefix != nil {
				nested += *f.Flags.Prefix
			} else {
				nested += key + "_"
			}
			embedded := pointer.Deref(fv)
			if err := b.process(embedded, nested, lookup); err != nil {
				return err
			}
			continue
		}

		// Regular field
		key = prefix + key
		val, ok := lookup(key)
		if !ok {
			switch {
			case f.Flags.Default != "":
				val = f.Flags.Default
			case f.Flags.Required:
				return fmt.Errorf("required key %q is missing", key)
			default:
				continue
			}
		}

		if err := setValue(fv, val, f.Flags); err != nil {
			return fmt.Errorf(
				"error setting field %q from key %q: %w",
				f.StructFieldName, key, err,
			)
		}
	}
	return nil
}

type meta struct {
	Index           int
	StructFieldName string
	Name            string
	Flags           *Flags
	Inline          bool
	Embedded        bool
	Err             error
}

func (b *Binder) buildMeta(rt reflect.Type) []meta {
	var fields []meta
	for i := 0; i < rt.NumField(); i++ {
		ft := rt.Field(i)

		if !ft.IsExported() {
			continue
		}

		val := ft.Tag.Get(b.name)
		if val == "-" {
			continue
		}

		flags, err := parse(val)
		if err != nil {
			fields = append(fields, meta{
				Err: fmt.Errorf(
					"failed to parse tag for field %q: %w", ft.Name, err,
				),
			})
			continue
		}

		m := meta{
			Index:           i,
			StructFieldName: ft.Name,
			Name:            flags.Name,
			Flags:           flags,
			Inline:          ft.Anonymous && flags.Inline,
		}

		if m.Name == "" {
			m.Name = b.transform(ft.Name)
		}

		m.Embedded = isEmbedded(ft)

		fields = append(fields, m)
	}

	return fields
}

// Flags encapsulates the options parsed from a tag.
type Flags struct {
	Name     string
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
	f := &Flags{Name: t.Name, Split: ","}

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
