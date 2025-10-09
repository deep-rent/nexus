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
//		Proxy    ProxyConfig   `env:"prefix:'HTTP_PROXY_'"`
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
	"unicode"
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

type flags struct {
	Name     string
	Prefix   *string
	Split    string
	Unit     string
	Format   string
	Default  string
	Inline   bool
	Required bool
}

type config struct {
	Prefix string
	Lookup Lookup
}

var (
	typeTime        = reflect.TypeOf(time.Time{})
	typeDuration    = reflect.TypeOf(time.Duration(0))
	typeURL         = reflect.TypeOf(url.URL{})
	typeUnmarshaler = reflect.TypeOf((*Unmarshaler)(nil)).Elem()
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
			if err := process(fv, prefix, lookup); err != nil {
				return err
			}
			continue
		}

		key := opts.Name
		if key == "" {
			key = snake(ft.Name)
		}

		// Check for true embedded structs.
		if ft.Type.Kind() == reflect.Struct &&
			!isUnmarshalable(fv) && ft.Type != typeTime && ft.Type != typeURL {
			nested := prefix
			if opts.Prefix != nil {
				nested += *opts.Prefix
			} else {
				nested += key + "_"
			}
			if err := process(fv, nested, lookup); err != nil {
				return err
			}
			continue
		}

		key = prefix + key
		val, ok := lookup(key)
		if !ok {
			if opts.Default != "" {
				val = opts.Default
			} else if opts.Required {
				return fmt.Errorf("required variable %q is not set", key)
			} else {
				continue
			}
		}

		if err := setValue(fv, val, opts); err != nil {
			return fmt.Errorf(
				"error setting field %q from variable %q: %w",
				ft.Name, key, err,
			)
		}
	}
	return nil
}

func setValue(rv reflect.Value, v string, opts flags) error {
	// Case 1: The field's type directly implements Unmarshaler.
	// This works for pointer types (e.g., *reverse) or value types with
	// value receivers.
	if rv.Type().Implements(typeUnmarshaler) {
		if rv.Kind() == reflect.Pointer && rv.IsNil() {
			rv.Set(reflect.New(rv.Type().Elem()))
		}
		return rv.Interface().(Unmarshaler).UnmarshalEnv(v)
	}
	// Case 2: A pointer to the field's type implements Unmarshaler.
	// This works for value types with pointer receivers (e.g., reverse).
	if rv.CanAddr() && rv.Addr().Type().Implements(typeUnmarshaler) {
		return rv.Addr().Interface().(Unmarshaler).UnmarshalEnv(v)
	}
	rv = deref(rv)
	switch rv.Type() {
	case typeTime:
		return setTime(rv, v, opts)
	case typeDuration:
		return setDuration(rv, v, opts)
	case typeURL:
		return setURL(rv, v)
	default:
		return setOther(rv, v, opts)
	}
}

// setOther handles all other supported primitive and slice types by delegating
// to the appropriate parsing logic.
func setOther(rv reflect.Value, v string, opts flags) error {
	switch kind := rv.Kind(); kind {
	case reflect.String:
		rv.SetString(v)
		return nil
	case reflect.Bool:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("%q is not a bool", v)
		}
		rv.SetBool(b)
		return nil
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
		return nil
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
		return nil
	case reflect.Float32, reflect.Float64:
		b := rv.Type().Bits()
		f, err := strconv.ParseFloat(v, b)
		if err != nil {
			return fmt.Errorf("%q is not a float%d", v, b)
		}
		rv.SetFloat(f)
		return nil
	case reflect.Complex64, reflect.Complex128:
		b := rv.Type().Bits()
		c, err := strconv.ParseComplex(v, b)
		if err != nil {
			return fmt.Errorf("%q is not a complex%d", v, b)
		}
		rv.SetComplex(c)
		return nil
	case reflect.Slice:
		return setSlice(rv, v, opts)
	default:
		return fmt.Errorf("unsupported type: %s", kind)
	}
}

// setTime parses and sets a time.Time value based on the provided format and
// unit options.
func setTime(rv reflect.Value, v string, opts flags) error {
	var t time.Time
	var err error
	switch format := opts.Format; format {
	case "unix":
		var i int64
		i, err = strconv.ParseInt(v, 10, 64)
		if err == nil {
			switch unit := opts.Unit; unit {
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
func setDuration(rv reflect.Value, v string, opts flags) error {
	var d time.Duration
	var err error
	if unit := opts.Unit; unit == "" {
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
func setSlice(rv reflect.Value, v string, opts flags) error {
	if rv.Type().Elem().Kind() == reflect.Uint8 {
		var b []byte
		var err error
		switch opts.Format {
		case "":
			b = []byte(v)
		case "hex":
			b, err = hex.DecodeString(v)
		case "base32":
			b, err = base32.StdEncoding.DecodeString(v)
		case "base64":
			b, err = base64.StdEncoding.DecodeString(v)
		default:
			return fmt.Errorf("unsupported format for []byte: %q", opts.Format)
		}
		if err != nil {
			return err
		}
		rv.SetBytes(b)
		return nil
	}

	parts := strings.Split(v, opts.Split)
	if len(parts) == 1 && parts[0] == "" {
		rv.Set(reflect.MakeSlice(rv.Type(), 0, 0))
		return nil
	}

	slice := reflect.MakeSlice(rv.Type(), len(parts), len(parts))
	for i, part := range parts {
		if err := setValue(slice.Index(i), part, opts); err != nil {
			return fmt.Errorf("failed to parse slice element at index %d: %w", i, err)
		}
	}

	rv.Set(slice)
	return nil
}

// parse parses the `env` tag string. It supports quoted values for options
// to allow commas within them, e.g., `default:'a,b,c'`.
func parse(s string) (opts flags, err error) {
	opts.Split = ","

	// The first part is always the variable name.
	name, rest, _ := strings.Cut(s, ",")
	opts.Name = name

	// Scan through the remaining options.
	for rest != "" {
		// Trim leading space from the rest of the string.
		rest = strings.TrimLeftFunc(rest, unicode.IsSpace)
		if rest == "" {
			break
		}

		// Find the end of the current option part by finding the next
		// comma that is not inside quotes.
		end := -1
		inQuote := false
		var q rune
		for i, r := range rest {
			if r == q {
				inQuote = false
				q = 0
			} else if !inQuote && (r == '\'' || r == '"') {
				inQuote = true
				q = r
			} else if !inQuote && r == ',' {
				end = i
				break
			}
		}

		var part string
		if end == -1 {
			// This is the last option part.
			part = rest
			rest = ""
		} else {
			part = rest[:end]
			rest = rest[end+1:]
		}

		// Now, parse the individual part (e.g., "default:'foo,bar'").
		key, val, found := strings.Cut(part, ":")
		key = strings.TrimSpace(key)
		if !found {
			// This is a boolean flag like "inline" or "required".
			switch key {
			case "inline":
				opts.Inline = true
			case "required":
				opts.Required = true
			case "":
				// An empty part can result from trailing or double commas. Ignore it.
			default:
				return opts, fmt.Errorf("unknown tag option: %q", key)
			}
			continue
		}
		val = unquote(val)
		switch key {
		case "format":
			opts.Format = val
		case "prefix":
			opts.Prefix = &val
		case "split":
			opts.Split = val
		case "unit":
			opts.Unit = val
		case "default":
			opts.Default = val
		default:
			return opts, fmt.Errorf("unknown tag option: %q", key)
		}
	}
	return opts, nil
}

// isUnmarshalable checks if a type implements the Unmarshaler interface.
func isUnmarshalable(v reflect.Value) bool {
	// A value can only satisfy an interface if it's addressable,
	// so we check if a pointer to the value's type implements it.
	return v.CanAddr() && reflect.PointerTo(v.Type()).Implements(typeUnmarshaler)
}

// deref follows pointers until it reaches a non-pointer, allocating if nil.
// If an un-settable nil pointer is encountered (e.g., a nil pointer inside
// an unexported field of a struct), the function stops dereferencing and
// returns the non-settable nil pointer to prevent a panic.
func deref(v reflect.Value) reflect.Value {
	// Loop through multi-level pointers to handle cases like **int.
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			if !v.CanSet() {
				break
			}
			v.Set(reflect.New(v.Type().Elem()))
		}
		v = v.Elem()
	}
	return v
}

// unquote removes a single layer of surrounding single or double quotes from a
// string. If the string is not quoted or is too short, it is returned
// unchanged.
func unquote(s string) string {
	if len(s) < 2 {
		return s
	}
	// Check for a matching pair of quotes.
	switch s[0] {
	case '"':
		if s[len(s)-1] == '"' {
			return s[1 : len(s)-1]
		}
	case '\'':
		if s[len(s)-1] == '\'' {
			return s[1 : len(s)-1]
		}
	}
	// Return the original string if no matching quotes are found.
	return s
}

// snake converts a camelCase string to an uppercase SNAKE_CASE string.
// For example: "myVariable" -> "MY_VARIABLE", "APIService" -> "API_SERVICE".
func snake(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 5)
	runes := []rune(s)
	for i, r := range runes {
		// Insert an underscore before a capital letter or digit.
		if i != 0 {
			q := runes[i-1]
			if (unicode.IsLower(q) &&
				// Case 1: Lowercase to uppercase/digit transition ("myVar", "myVar1").
				(unicode.IsUpper(r) || unicode.IsDigit(r))) ||
				(unicode.IsUpper(q) &&
					// Case 2: Acronym to new word transition ("MYVar").
					unicode.IsUpper(r) &&
					i+1 < len(runes) &&
					unicode.IsLower(runes[i+1])) {
				b.WriteRune('_')
			}
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}
