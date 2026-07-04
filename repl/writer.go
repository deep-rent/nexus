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
	"encoding/json/v2"
)

type Handler[Tx any, T any] func(
	ctx context.Context,
	tx Tx,
	entityID UUID,
	time uint64,
	payload T,
) error

type Writer[Tx any] interface {
	Kind() Kind

	Handle(ctx context.Context, tx Tx, c Change) error
}

func NewWriter[Tx, T any](
	kind Kind,
	exec Handler[Tx, T],
) Writer[Tx] {
	return &writer[Tx, T]{
		kind: kind,
		exec: exec,
	}
}

type writer[Tx any, T any] struct {
	kind Kind
	exec Handler[Tx, T]
}

func (w *writer[Tx, T]) Kind() Kind {
	return w.kind
}

func (w *writer[Tx, T]) Handle(ctx context.Context, tx Tx, c Change) error {
	var payload T
	if err := json.Unmarshal(c.Payload, &payload); err != nil {
		return err
	}
	return w.exec(ctx, tx, c.EntityID, c.Time, payload)
}

var _ Writer[any] = (*writer[any, any])(nil)
