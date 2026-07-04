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

package repl

import (
	"context"
)

// Fetcher abstracts data retrieval for a specific entity type.
type Fetcher[Tx any] interface {
	Entity() Entity
	Fetch(ctx context.Context, tx Tx, since uint64) (
		updates any,
		deletes []UUID,
		err error,
	)
}

// fetcher is a generic implementation of Fetcher.
type fetcher[Tx any, T any] struct {
	entity Entity
	fetch  func(ctx context.Context, tx Tx, since uint64) ([]T, []UUID, error)
}

func (f *fetcher[Tx, T]) Entity() Entity { return f.entity }

func (f *fetcher[Tx, T]) Fetch(
	ctx context.Context,
	tx Tx,
	since uint64,
) (any, []UUID, error) {
	return f.fetch(ctx, tx, since)
}

// NewFetcher creates a new typed Fetcher.
func NewFetcher[Tx, T any](
	entity Entity,
	fetch func(ctx context.Context, tx Tx, since uint64) ([]T, []UUID, error),
) Fetcher[Tx] {
	return &fetcher[Tx, T]{
		entity: entity,
		fetch:  fetch,
	}
}
