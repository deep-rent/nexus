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

package bind

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
