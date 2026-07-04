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

package delta

import (
	"context"
)

type Fetcher[Tx any, T any] func(
	ctx context.Context,
	tx Tx,
	since uint64,
) ([]T, []UUID, error)

// Reader abstracts data retrieval for a specific entity type.
type Reader[Tx any] interface {
	Entity() Entity

	Fetch(ctx context.Context, tx Tx, since uint64) (
		updates any,
		deletes []UUID,
		err error,
	)
}

// NewReader creates a new typed [Reader].
func NewReader[Tx, T any](
	entity Entity,
	fetch Fetcher[Tx, T],
) Reader[Tx] {
	return &reader[Tx, T]{
		entity: entity,
		fetch:  fetch,
	}
}

// reader is a generic implementation of [Reader].
type reader[Tx any, T any] struct {
	entity Entity
	fetch  Fetcher[Tx, T]
}

func (f *reader[Tx, T]) Entity() Entity { return f.entity }

func (f *reader[Tx, T]) Fetch(
	ctx context.Context,
	tx Tx,
	since uint64,
) (any, []UUID, error) {
	return f.fetch(ctx, tx, since)
}

var _ Reader[any] = (*reader[any, any])(nil)
