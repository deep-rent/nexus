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
// Example:
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
// Option "default": Sets a default value to be used if the environment
// variable is not set.
//
//	Port int `env:",default:8080"`
//
// Option "required": Marks the variable as required. [Unmarshal] will return
// an error if the variable is not set and no default is provided.
//
//	APIKey string `env:",required"`
//
// Option "prefix": For nested struct fields, this overrides the default
// prefix. By default, the prefix is the field's name in SNAKE_CASE followed by
// an underscore. It can be set to an empty string to omit the prefix entirely.
//
//	DBConfig `env:",prefix:DB_"`
//
// Option "inline": When applied to an anonymous struct field, it flattens the
// struct, effectively treating its fields as if they belonged to the parent
// struct.
//
//	Nested `env:",inline"`
//
// Option "split": For slice types, this specifies the delimiter to split the
// environment variable string. The default separator is a comma.
//
//	Hosts []string `env:",split:';'"`
//
// Option "format": Provides a format specifier for special types. For
// [time.Time] it can be a Go-compliant layout string (e.g., "2006-01-02") or
// one of the predefined constants "unix", "dateTime", "date", and "time".
// Defaults to the RFC 3339 format. For []byte, it can be "hex", "base32", or
// "base64" to alter the encoding format.
//
//	StartDate time.Time `env:",format:date"`
//
// Option "unit": Specifies the unit for [time.Time] or [time.Duration] when
// parsing from an integer. For [time.Duration]: "ns", "us" (or "μs"), "ms",
// "s", "m", "h". For [time.Time] (with format:unix): "s", "ms", "us" (or "μs").
//
//	CacheTTL time.Duration `env:",unit:m,default:5"`
package env
