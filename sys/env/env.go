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

package env

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/deep-rent/nexus/std/ascii"
	"github.com/deep-rent/nexus/dat/bind"
	"github.com/deep-rent/nexus/std/snake"
)

// Lookup is a function that retrieves the value of an environment variable.
// It follows the signature of [os.LookupEnv], returning the value and a boolean
// indicating whether the variable was present. This type allows for custom
// lookup mechanisms, such as reading from sources other than the actual
// environment, which is especially useful for testing.
type Lookup func(key string) (string, bool)

// Option is a functional option for configuring the [Unmarshal] behavior.
type Option func(*config)

// WithPrefix sets a prefix that will be prepended to all environment variable
// keys before looking them up. If not provided, no prefix is used.
func WithPrefix(prefix string) Option {
	return func(c *config) {
		c.Prefix = prefix
	}
}

// WithLookup overrides the default mechanism for retrieving environment
// variables. By default, [Unmarshal] uses [os.LookupEnv]. This option is
// particularly useful for unit tests, allowing you to inject a mock environment
// or an alternative configuration source.
func WithLookup(lookup Lookup) Option {
	return func(c *config) {
		if lookup != nil {
			c.Lookup = lookup
		}
	}
}

// config holds configuration options for environment variable processing.
type config struct {
	// Prefix is a common prefix for all environment variable keys.
	Prefix string
	// Lookup is the injectable callback for variable lookup.
	Lookup Lookup
}

// binder is shared by every call to [Unmarshal]. Caching the reflection
// metadata is safe because a type's tags cannot change, and it keeps a
// process that unmarshals repeatedly from re-walking the same structs.
var binder = bind.New(
	"env",
	bind.WithTransformer(snake.ToUpper),
	bind.WithCache(true),
)

type source struct {
	lookup Lookup
}

func (s source) Lookup(key string) ([]string, bool) {
	if val, ok := s.lookup(key); ok {
		return []string{val}, true
	}
	return nil, false
}

var _ bind.Source = (*source)(nil)

// Unmarshal populates the fields of a struct with values from environment
// variables. The given value v must be a non-nil pointer to a struct.
//
// By default, [Unmarshal] processes all exported fields. A field's environment
// variable name is derived from its name, converted to uppercase SNAKE_CASE.
// To ignore a field, tag it with `env:"-"`. Unexported fields are always
// excluded. If a variable is not set, the field remains unchanged unless a
// default value is specified in the struct tag, or it is marked as required.
//
// Every problem found is reported together, so a misconfigured environment
// can be corrected in one pass rather than one variable per attempt. Use
// [errors.Join] semantics to inspect the result.
func Unmarshal[T any](v *T, opts ...Option) error {
	cfg := config{
		Lookup: os.LookupEnv,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return binder.Bind(v, cfg.Prefix, source{cfg.Lookup})
}

// Expand substitutes environment variables in a string.
//
// It replaces references to environment variables in the formats ${KEY} or $KEY
// with their corresponding values. A literal dollar sign can be escaped with $$
// (double dollar sign). If a referenced variable is not found in the
// environment, the function returns an error. Its behavior can be adjusted
// through functional options.
func Expand(s string, opts ...Option) (string, error) {
	cfg := config{
		Lookup: os.LookupEnv,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	var b bytes.Buffer
	b.Grow(len(s))

	i := 0
	for i < len(s) {
		// Find the next dollar sign.
		j := i
		for j < len(s) && s[j] != '$' {
			j++
		}

		// Append the literal part before the dollar sign.
		b.WriteString(s[i:j])
		i = j

		// If there is no dollar sign left, we are done.
		if i >= len(s) {
			break
		}

		// Look at the character after the dollar sign.
		if i+1 < len(s) && s[i+1] == '$' { //nolint:gocritic
			// Handle the `$$` escape sequence.
			b.WriteByte('$')
			i += 2
		} else if i+1 < len(s) && s[i+1] == '{' {
			// Handle the `${VAR}` syntax.
			// Find the closing brace.
			end := 2
			for i+end < len(s) && s[i+end] != '}' {
				end++
			}
			if i+end == len(s) {
				return "", errors.New("variable bracket not closed")
			} else {
				// Extract the bracketed variable name.
				key := cfg.Prefix + s[i+2:i+end]
				val, ok := cfg.Lookup(key)
				if !ok {
					return "", fmt.Errorf("variable %q is not set", key)
				}
				b.WriteString(val)
				// Move the index past the processed variable `${KEY}`.
				i += end + 1
			}
		} else {
			// Handle the `$VAR` syntax.
			// Find the end of the variable name. The first character of a
			// variable must be a letter or underscore; subsequent characters
			// an include digits.
			n := 0
			for j := i + 1; j < len(s); j++ {
				c := s[j]
				if ascii.IsAlpha(c) || c == '_' || (n > 0 && ascii.IsDigit(c)) {
					n++
				} else {
					break
				}
			}

			if n == 0 {
				// No valid identifier characters found (e.g., "$5", "$!").
				// Treat as a literal dollar sign.
				b.WriteByte('$')
				i++
			} else {
				// Extract the unbracketed variable name.
				key := cfg.Prefix + s[i+1:i+1+n]
				val, ok := cfg.Lookup(key)
				if !ok {
					return "", fmt.Errorf("variable %q is not set", key)
				}
				b.WriteString(val)
				// Move the index past the processed variable `$KEY`.
				i += 1 + n
			}
		}
	}

	return b.String(), nil
}
