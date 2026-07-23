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
