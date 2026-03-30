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

package mock

import (
	"github.com/deep-rent/nexus/migrate"
)

// Source is an in-memory implementation of migrate.Source.
// It allows you to pre-define the list of scripts and optionally inject an
// error to test failure paths.
type Source struct {
	Scripts []migrate.SourceScript
	ListErr error
}

// NewSource creates a new in-memory Source with the provided scripts.
func NewSource(scripts ...migrate.SourceScript) *Source {
	return &Source{
		Scripts: scripts,
	}
}

// List returns the pre-configured scripts or the injected ListErr.
func (s *Source) List() ([]migrate.SourceScript, error) {
	if s.ListErr != nil {
		return nil, s.ListErr
	}

	// Return a copy to prevent accidental mutation by the caller.
	out := make([]migrate.SourceScript, len(s.Scripts))
	copy(out, s.Scripts)
	return out, nil
}

// Ensure Source satisfies the migrate.Source interface.
var _ migrate.Source = (*Source)(nil)
