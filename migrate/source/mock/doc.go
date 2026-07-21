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

// Package mock provides an in-memory implementation of the migrate.Source.
//
// It is designed strictly for unit testing: it allows developers to simulate
// various migration scenarios, including success paths and error conditions,
// without requiring access to a physical filesystem or external storage.
//
// # Usage
//
// Initialize the source with predefined scripts and use it in place of a real
// source in your migration tests.
//
// Example:
//
//	src := mock.New(migrate.SourceScript{
//	    Version:     1,
//	    Description: "init",
//	    Direction:   migrate.Up,
//	    Content:     []byte("..."),
//	})
package mock
