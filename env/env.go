// Package env provides functionality for unmarshaling environment variables
// into Go structs.
//
// By default, all exported fields in a struct are mapped to environment
// variables. The variable name is derived by converting the field's name to
// uppercase SNAKE_CASE (e.g., a field named APIKey maps to API_KEY).
// This behavior can be customized or disabled on a per-field basis using
// struct tags.
//
// # Usage
//
// Define a struct to hold your configuration. Only exported fields will be
// considered. The code snippet below showcases various field types and
// struct tag options:
//
//	type Config struct {
//		Host     string        `env:",required"`
//		Port     int           `env:",default:8080"`
//		Timeout  time.Duration `env:",unit:s"`
//		Debug    bool
//		Proxy    ProxyConfig   `env:",prefix:'HTTP_PROXY_'"`
//		Roles    []string      `env:",split:';'"`
//		Internal int           `env:"-"`
//		internal int
//	}
//
//	var cfg Config
//	if err := env.Unmarshal(&cfg); err != nil {
//		log.Fatalf("failed to unmarshal config: %v", err)
//	}
//	// Use the configuration to bootstrap your application...
//
// # Options
//
// The behavior of the unmarshaler is controlled by the env struct field tag.
// The tag is a comma-separated string of options.
//
// The first value is the name of the environment variable. If it is omitted,
// the field's name is used as the base for the variable name.
//
//	DatabaseURL string `env:"MY_DATABASE_URL"`
//
// The subsequent parts of the tag are options, which can be in a key:value
// format or be boolean flags.
//
// Option "default"
//
// Sets a default value to be used if the environment variable is not set.
//
//	Port int `env:",default:8080"`
//
// Option "required"
//
// Marks the variable as required. Unmarshal will return an error if the
// variable is not set and no default is provided.
//
//	APIKey string `env:",required"`
//
// Option "prefix"
//
// For nested struct fields, this overrides the default prefix. By default,
// the prefix is the field's name in SNAKE_CASE followed by an underscore.
// It can be set to an empty string to omit the prefix entirely.
//
//	DBConfig `env:",prefix:DB_"`
//
// Option "inline"
//
// When applied to an anonymous struct field, it flattens the struct,
// effectively treating its fields as if they belonged to the parent struct.
//
//	Nested `env:",inline"`
//
// Option "split"
//
// For slice types, this specifies the delimiter to split the environment
// variable string. The default separator is a comma.
//
//	Hosts []string `env:",split:';'"`
//
// Option "format"
//
// Provides a format specifier for special types. For time.Time it can
// be a Go-compliant layout string (e.g., "2006-01-02") or one of the predefined
// constants "unix", "dateTime", "date", and "time". Defaults to the RFC
// 3339 format. For []byte, it can be "hex", "base32", or "base64" to alter
// the encoding format.
//
//	StartDate time.Time `env:",format:date"`
//
// Option "unit"
//
// Specifies the unit for time.Time or time.Duration when parsing from an
// integer. For time.Duration: "ns", "us" (or "μs"), "ms", "s", "m", "h".
// For time.Time (with format:unix): "s", "ms", "us" (or "μs").
//
//	CacheTTL time.Duration `env:",unit:m,default:5"`
package env

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/deep-rent/nexus/internal/pointer"
	"github.com/deep-rent/nexus/internal/snake"
	"github.com/deep-rent/nexus/internal/tag"
)

// Lookup is a function that retrieves the value of an environment variable.
// It follows the signature of os.LookupEnv, returning the value and a boolean
// indicating whether the variable was present. This type allows for custom
// lookup mechanisms, such as reading from sources other than the actual
// environment, which is especially useful for testing.
type Lookup func(key string) (string, bool)

// Unmarshaler is an interface that can be implemented by types to provide their
// own custom logic for parsing an environment variable string.
type Unmarshaler interface {
	// UnmarshalEnv unmarshals the string value of an environment variable.
	// The value is the raw string from the environment or a default value.
	// It returns an error if the value cannot be parsed.
	UnmarshalEnv(value string) error
}

// Option is a function that configures the behavior of the Unmarshal and Expand
// functions. It follows the functional options pattern.
type Option func(*config)

// WithPrefix returns an Option that adds a common prefix to all environment
// variable keys looked up during unmarshaling. For example, WithPrefix("APP_")
// would cause a field with the env tag "PORT" to look for the "APP_PORT"
// variable.
func WithPrefix(prefix string) Option {
	return func(o *config) {
		o.Prefix = prefix
	}
}

// WithLookup returns an Option that sets a custom lookup function for
// retrieving environment variable values. If not customized, os.LookupEnv will
// be used by default. This is useful for testing or if you need to load
// environment variables from alternative sources.
func WithLookup(lookup Lookup) Option {
	return func(o *config) {
		if lookup != nil {
			o.Lookup = lookup
		}
	}
}

// Unmarshal populates the fields of a struct with values from environment
// variables. The given value v must be a non-nil pointer to a struct.
//
// By default, Unmarshal processes all exported fields. A field's environment
// variable name is derived from its name, converted to uppercase SNAKE_CASE.
// To ignore a field, tag it with `env:"-"`. Unexported fields are always
// excluded. If a variable is not set, the field remains unchanged unless a
// default value is specified in the struct tag, or it is marked as required.
func Unmarshal(v any, opts ...Option) error {
	if err := unmarshal(v, opts...); err != nil {
		return fmt.Errorf("env: %w", err)
	}
	return nil
}

// Expand substitutes environment variables in a string.
//
// It replaces references to environment variables in the format ${KEY} with
// their corresponding values. A literal dollar sign can be escaped with $$.
// If a referenced variable is not found in the environment, the function
// returns an error. Its behavior can be adjusted through functional options.
func Expand(s string, opts ...Option) (string, error) {
	cfg := config{
		Lookup: os.LookupEnv,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	var b strings.Builder
	b.Grow(len(s))

	i := 0
	for i < len(s) {
		// Find the next dollar sign.
		start := strings.IndexByte(s[i:], '$')
		if start == -1 {
			b.WriteString(s[i:])
			break
		}

		// Append the text before the dollar sign.
		b.WriteString(s[i : i+start])

		// Move our main index to the location of the dollar sign.
		i += start

		// Check what follows the dollar sign.
		switch {
		case i+1 < len(s) && s[i+1] == '$':
			// Case 1: Escaped dollar sign ($$).
			b.WriteByte('$')
			i += 2 // Skip both signs.

		case i+1 < len(s) && s[i+1] == '{':
			// Case 2: Variable expansion (${KEY}).
			end := strings.IndexByte(s[i+2:], '}')
			if end == -1 {
				return "", errors.New("env: variable bracket not closed")
			}
			// Extract the variable name.
			key := cfg.Prefix + s[i+2:i+2+end]
			val, ok := cfg.Lookup(key)
			if !ok {
				return "", fmt.Errorf("env: variable %q is not set", key)
			}
			b.WriteString(val)
			// Move the index past the processed variable `${KEY}`.
			i += 2 + end + 1

		default:
			// Case 3: Lone dollar sign. Treat it literally.
			b.WriteByte('$')
			i++
		}
	}

	return b.String(), nil
}

// flags encapsulates the options parsed from an `env` struct tag.
type flags struct {
	Name     string  // Name of the environment variable.
	Prefix   *string // Optional prefix for nested structs.
	Split    string  // Delimiter for slice types.
	Unit     string  // Unit for time.Time or time.Duration.
	Format   string  // Format specifier for special types.
	Default  string  // Fallback value if the variable is not found.
	Inline   bool    // Whether to inline an anonymous struct field.
	Required bool    // Whether the variable is required.
}

type config struct {
	Prefix string // Common prefix for all environment variable keys.
	Lookup Lookup // Injectable callback for variable lookup.
}

// Cache types with special unmarshaling logic.
var (
	typeTime        = reflect.TypeFor[time.Time]()
	typeDuration    = reflect.TypeFor[time.Duration]()
	typeURL         = reflect.TypeFor[url.URL]()
	typeUnmarshaler = reflect.TypeFor[Unmarshaler]()
)

func unmarshal(v any, opts ...Option) error {
	ptr := reflect.ValueOf(v)
	if ptr.Kind() != reflect.Pointer || ptr.IsNil() {
		return errors.New(
			"expected a non-nil pointer to a struct",
		)
	}
	val := ptr.Elem()
	if kind := val.Kind(); kind != reflect.Struct {
		return fmt.Errorf(
			"expected a pointer to a struct, but got pointer to %v", kind,
		)
	}
	cfg := config{
		Lookup: os.LookupEnv,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return process(val, cfg.Prefix, cfg.Lookup)
}

// process recursively walks through the struct fields.
func process(rv reflect.Value, prefix string, lookup Lookup) error {
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		ft := rt.Field(i)
		fv := rv.Field(i)

		if !ft.IsExported() || !fv.CanSet() {
			continue
		}

		tag := ft.Tag.Get("env")
		if tag == "-" {
			continue
		}
		opts, err := parse(tag)
		if err != nil {
			return fmt.Errorf("failed to parse tag for field %q: %w", ft.Name, err)
		}

		if ft.Anonymous && opts.Inline {
			// Dereference and allocate in case the inline field is a pointer.
			embedded := pointer.Deref(fv)
			if err := process(embedded, prefix, lookup); err != nil {
				return err
			}
			continue
		}

		key := opts.Name
		if key == "" {
			key = snake.ToUpper(ft.Name)
		}

		// Check for true embedded structs.
		if isEmbedded(ft, fv) {
			nested := prefix
			if opts.Prefix != nil {
				nested += *opts.Prefix
			} else {
				nested += key + "_"
			}

			// Dereference and allocate in case the field is a pointer.
			embedded := pointer.Deref(fv)
			if err := process(embedded, nested, lookup); err != nil {
				return err
			}
			continue
		}

		key = prefix + key
		val, ok := lookup(key)
		// A variable is "set" even if it is empty. We only trigger the strictly
		// missing variable logic if 'ok' is false.
		if !ok {
			if opts.Default != "" {
				val = opts.Default
			} else if opts.Required {
				return fmt.Errorf("required variable %q is not set", key)
			} else {
				continue
			}
		} else if val == "" && opts.Default != "" {
			// If the variable is explicitly set to empty (""), but a default
			// exists in the tags, fall back to the default value.
			val = opts.Default
		}

		// If a field is required and set to "", it bypasses the errors above.
		// For strings, setValue will correctly assign the empty string. For types
		// like int or bool, setValue will return a natural parsing error.
		if err := setValue(fv, val, opts); err != nil {
			return fmt.Errorf(
				"error setting field %q from variable %q: %w",
				ft.Name, key, err,
			)
		}
	}
	return nil
}

func setValue(rv reflect.Value, v string, f *flags) error {
	if u, ok := asUnmarshaler(rv); ok {
		// Use the custom unmarshaler if available.
		return u.UnmarshalEnv(v)
	}
	rv = pointer.Deref(rv)
	switch rv.Type() {
	case typeTime:
		return setTime(rv, v, f)
	case typeDuration:
		return setDuration(rv, v, f)
	case typeURL:
		return setURL(rv, v)
	default:
		return setOther(rv, v, f)
	}
}

// setOther handles all "regular" (primitive and slice) types by delegating to
// the appropriate parsing logic based on the reflective kind. If rv is a slice,
// it calls setSlice, otherwise it attempts to convert v into the type expected
// by rv and sets it.
func setOther(rv reflect.Value, v string, f *flags) error {
	switch kind := rv.Kind(); kind {
	case reflect.Slice:
		return setSlice(rv, v, f)
	case reflect.Bool:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("%q is not a bool", v)
		}
		rv.SetBool(b)
	case reflect.String:
		rv.SetString(v)
	case
		reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64:
		b := rv.Type().Bits()
		i, err := strconv.ParseInt(v, 10, b)
		if err != nil {
			return fmt.Errorf("%q is not an int%d", v, b)
		}
		rv.SetInt(i)
	case
		reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64:
		b := rv.Type().Bits()
		u, err := strconv.ParseUint(v, 10, b)
		if err != nil {
			return fmt.Errorf("%q is not a uint%d", v, b)
		}
		rv.SetUint(u)
	case reflect.Float32, reflect.Float64:
		b := rv.Type().Bits()
		f, err := strconv.ParseFloat(v, b)
		if err != nil {
			return fmt.Errorf("%q is not a float%d", v, b)
		}
		rv.SetFloat(f)
	case reflect.Complex64, reflect.Complex128:
		b := rv.Type().Bits()
		c, err := strconv.ParseComplex(v, b)
		if err != nil {
			return fmt.Errorf("%q is not a complex%d", v, b)
		}
		rv.SetComplex(c)
	default:
		return fmt.Errorf("unsupported type: %s", kind)
	}
	return nil
}

// setTime parses and sets a time.Time value based on the provided format and
// unit options.
func setTime(rv reflect.Value, v string, f *flags) error {
	var t time.Time
	var err error
	switch format := f.Format; format {
	case "unix":
		var i int64
		i, err = strconv.ParseInt(v, 10, 64)
		if err == nil {
			switch unit := f.Unit; unit {
			case "s", "":
				t = time.Unix(i, 0)
			case "ms":
				t = time.UnixMilli(i)
			case "us", "μs":
				t = time.UnixMicro(i)
			default:
				err = fmt.Errorf("invalid time unit: %q", unit)
			}
		}
	case "dateTime":
		t, err = time.Parse(time.DateTime, v)
	case "date":
		t, err = time.Parse(time.DateOnly, v)
	case "time":
		t, err = time.Parse(time.TimeOnly, v)
	case "":
		format = time.RFC3339
		fallthrough
	default:
		t, err = time.Parse(format, v)
	}
	if err != nil {
		return err
	}
	rv.Set(reflect.ValueOf(t))
	return nil
}

// setDuration parses and sets a time.Duration value based on the provided unit
// option.
func setDuration(rv reflect.Value, v string, f *flags) error {
	var d time.Duration
	var err error
	if unit := f.Unit; unit == "" {
		d, err = time.ParseDuration(v)
	} else {
		var i int64
		i, err = strconv.ParseInt(v, 10, 64)
		if err == nil {
			switch unit {
			case "ns":
				d = time.Duration(i)
			case "us", "μs":
				d = time.Duration(i) * time.Microsecond
			case "ms":
				d = time.Duration(i) * time.Millisecond
			case "s":
				d = time.Duration(i) * time.Second
			case "m":
				d = time.Duration(i) * time.Minute
			case "h":
				d = time.Duration(i) * time.Hour
			default:
				err = fmt.Errorf("invalid duration unit: %q", unit)
			}
		}
	}
	if err != nil {
		return err
	}
	rv.SetInt(int64(d))
	return nil
}

// setURL parses and sets a url.URL value.
func setURL(rv reflect.Value, v string) error {
	u, err := url.Parse(v)
	if err != nil {
		return err
	}
	rv.Set(reflect.ValueOf(*u))
	return nil
}

// setSlice parses and sets a slice value. It supports []byte with special
// encoding formats, as well as other slice types by splitting the input string.
func setSlice(rv reflect.Value, v string, f *flags) error {
	if rv.Type().Elem().Kind() == reflect.Uint8 {
		var b []byte
		var err error
		switch f.Format {
		case "":
			b = []byte(v)
		case "hex":
			b, err = hex.DecodeString(v)
		case "base32":
			b, err = base32.StdEncoding.DecodeString(v)
		case "base64":
			b, err = base64.StdEncoding.DecodeString(v)
		default:
			return fmt.Errorf("unsupported format for []byte: %q", f.Format)
		}
		if err != nil {
			return err
		}
		rv.SetBytes(b)
		return nil
	}

	parts := strings.Split(v, f.Split)
	if len(parts) == 1 && parts[0] == "" {
		rv.Set(reflect.MakeSlice(rv.Type(), 0, 0))
		return nil
	}

	slice := reflect.MakeSlice(rv.Type(), len(parts), len(parts))
	for i, part := range parts {
		if err := setValue(slice.Index(i), part, f); err != nil {
			return fmt.Errorf("failed to parse slice element at index %d: %w", i, err)
		}
	}

	rv.Set(slice)
	return nil
}

// parse parses the `env` tag string. It supports quoted values for options
// to allow commas within them, e.g., `default:'a,b,c'`.
func parse(s string) (*flags, error) {
	t := tag.Parse(s)
	f := &flags{Name: t.Name, Split: ","}

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
func isEmbedded(f reflect.StructField, rv reflect.Value) bool {
	t := f.Type

	// Unwrap pointer(s) to check the underlying type.
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	// 1. It must resolve to a struct.
	if t.Kind() != reflect.Struct {
		return false
	}
	// 2. It is not one of the special struct types we handle directly.
	if t == typeTime || t == typeURL {
		return false
	}
	// 3. It does NOT implement the Unmarshaler interface.
	if _, ok := asUnmarshaler(rv); ok {
		return false
	}
	// If all checks pass, it's a struct we should recurse into.
	return true
}

// asUnmarshaler checks if the given reflect.Value implements the Unmarshaler
// interface, either directly or via a pointer receiver. If it does, the
// function returns the type-casted Unmarshaler and true. Otherwise, it returns
// nil and false.
func asUnmarshaler(rv reflect.Value) (Unmarshaler, bool) {
	// Case 1: The field's type directly implements Unmarshaler.
	// This works for pointer types (e.g., *reverse) or value types with
	// value receivers.
	if rv.Type().Implements(typeUnmarshaler) {
		if rv.Kind() == reflect.Pointer && rv.IsNil() {
			// If it's a nil pointer, we must allocate it to prevent a panic
			// when calling the interface method on the nil receiver.
			pointer.Alloc(rv)
		}
		return rv.Interface().(Unmarshaler), true
	}
	// Case 2: A pointer to the field's type implements Unmarshaler.
	// This works for value types with pointer receivers (e.g., reverse).
	if rv.CanAddr() && rv.Addr().Type().Implements(typeUnmarshaler) {
		return rv.Addr().Interface().(Unmarshaler), true
	}
	return nil, false
}
