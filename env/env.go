package env

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Lookup func(key string) (string, bool)

type Unmarshaler interface {
	UnmarshalEnv(value string) error
}

type Option func(*config)

func WithPrefix(prefix string) Option {
	return func(o *config) {
		o.Prefix = prefix
	}
}

func WithLookup(lookup Lookup) Option {
	return func(o *config) {
		if lookup != nil {
			o.Lookup = lookup
		}
	}
}

func Unmarshal(v any, opts ...Option) error {
	if err := unmarshal(v, opts...); err != nil {
		return fmt.Errorf("env: %w", err)
	}
	return nil
}

// Expand substitutes environment variables in a string with the format ${KEY}.
// It supports escaping the '$' character with '$$'. If a variable is not
// found, it returns an error.
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
				return "", errors.New("env: syntax error: unmatched '${' in string")
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
			key = toSnake(ft.Name)
		}
		key = prefix + key

		if ft.Type.Kind() == reflect.Struct &&
			!isUnmarshalable(fv) &&
			ft.Type != typeTime {
			if err := process(fv, key+"_", lookup); err != nil {
				return err
			}
			continue
		}

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
	if addr := rv.Addr(); addr.Type().Implements(typeUnmarshaler) {
		return addr.Interface().(Unmarshaler).UnmarshalEnv(v)
	}
	rv = deref(rv)
	switch rv.Type() {
	case typeTime:
		return setTime(rv, v, opts)
	case typeDuration:
		return setDuration(rv, v, opts)
	}
	return setPrimitive(rv, v, opts)
}

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

func setPrimitive(rv reflect.Value, v string, opts flags) error {
	switch rv.Kind() {
	case reflect.String:
		rv.SetString(v)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, err := strconv.ParseInt(v, 10, rv.Type().Bits())
		if err != nil {
			return err
		}
		rv.SetInt(i)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		u, err := strconv.ParseUint(v, 10, rv.Type().Bits())
		if err != nil {
			return err
		}
		rv.SetUint(u)
	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(v, rv.Type().Bits())
		if err != nil {
			return err
		}
		rv.SetFloat(f)
	case reflect.Bool:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return err
		}
		rv.SetBool(b)
	case reflect.Slice:
		return setSlice(rv, v, opts)
	default:
		return fmt.Errorf("unsupported type: %v", rv.Type())
	}
	return nil
}

func setSlice(rv reflect.Value, v string, opts flags) error {
	if rv.Type().Elem().Kind() == reflect.Uint8 {
		var b []byte
		var err error
		switch opts.Format {
		case "", "string":
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
		elem := slice.Index(i)
		if err := setValue(elem, part, opts); err != nil {
			return fmt.Errorf("failed to parse slice element at index %d: %w", i, err)
		}
	}

	rv.Set(slice)
	return nil
}

// parse parses the `env` tag string.
func parse(s string) (opts flags, err error) {
	opts.Split = ","
	name, rest, _ := strings.Cut(s, ",")
	opts.Name = name
	for rest != "" {
		var part string
		part, rest, _ = strings.Cut(rest, ",")
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "split:"); ok {
			opts.Split = v
		} else if v, ok := strings.CutPrefix(part, "unit:"); ok {
			opts.Unit = v
		} else if v, ok := strings.CutPrefix(part, "format:"); ok {
			opts.Format = v
		} else if v, ok := strings.CutPrefix(part, "default:"); ok {
			opts.Default = v
		} else if part == "inline" {
			opts.Inline = true
		} else if part == "required" {
			opts.Required = true
		} else if part != "" {
			return opts, fmt.Errorf("unknown tag option: %q", part)
		}
	}
	return opts, nil
}

// deref follows pointers until it reaches a non-pointer, allocating if nil.
func deref(rv reflect.Value) reflect.Value {
	// Loop through multi-level pointers to handle cases like **int.
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			rt := rv.Type().Elem()
			rv.Set(reflect.New(rt))
		}
		rv = rv.Elem()
	}
	return rv
}

// isUnmarshalable checks if a type implements the Unmarshaler interface.
func isUnmarshalable(v reflect.Value) bool {
	// A value can only satisfy an interface if it's addressable,
	// so we check if a pointer to the value's type implements it.
	return v.CanAddr() && reflect.PointerTo(v.Type()).Implements(typeUnmarshaler)
}

// toSnake converts a camelCase string to an uppercase SNAKE_CASE string.
func toSnake(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 5)
	runes := []rune(s)
	for i, r := range runes {
		// Insert an underscore before a capital letter or digit.
		if i != 0 {
			prev := runes[i-1]
			// Case 1: Lowercase to uppercase/digit transition (e.g, "myVar").
			if unicode.IsLower(prev) && unicode.IsUpper(r) || unicode.IsDigit(r) {
				b.WriteRune('_')
			}
			// Case 2: Acronym to new word transition (e.g., "MYVar").
			if unicode.IsUpper(prev) && unicode.IsUpper(r) &&
				i+1 < len(runes) && unicode.IsLower(runes[i+1]) {
				b.WriteRune('_')
			}
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}
