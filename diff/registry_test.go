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

package diff_test

import (
	"context"
	"slices"
	"testing"
	"uuid"

	"github.com/deep-rent/nexus/diff"
)

// noop is a do-nothing handler for registry tests.
type noop struct{}

func (noop) Upsert(context.Context, struct{}, diff.Scope, []diff.Op) error {
	return nil
}

func (noop) Delete(context.Context, struct{}, diff.Scope, []diff.Op) error {
	return nil
}

func (noop) Fetch(
	context.Context, struct{}, diff.Scope, diff.Window,
) ([]diff.Version, error) {
	return nil, nil
}

func (noop) Resolve(
	context.Context, struct{}, []uuid.UUID,
) (map[uuid.UUID]diff.Meta, error) {
	return nil, nil
}

var _ diff.Handler[struct{}] = (*noop)(nil)

type doc struct{}

func TestRegistry_Types_Deterministic(t *testing.T) {
	t.Parallel()

	names := []string{"asset", "address", "contract", "party", "sector"}

	build := func(order []string) *diff.Registry[struct{}] {
		r := diff.NewRegistry[struct{}]()
		for _, name := range order {
			switch name {
			case "asset":
				diff.Register[struct{}, doc](r, name, noop{},
					diff.WithRootMeta(), diff.WithParents("address"))
			case "contract":
				diff.Register[struct{}, doc](r, name, noop{},
					diff.WithOwner("asset", "asset_id"))
			case "address":
				diff.Register[struct{}, doc](r, name, noop{},
					diff.WithRootMeta())
			default:
				diff.Register[struct{}, doc](r, name, noop{},
					diff.WithRootMeta())
			}
		}
		return r
	}

	want := build(names).Types()

	pos := make(map[string]int)
	for i, name := range want {
		pos[name] = i
	}
	if pos["address"] > pos["asset"] {
		t.Error("address should come before asset")
	}
	if pos["asset"] > pos["contract"] {
		t.Error("asset should come before contract")
	}

	// The order must be independent of registration order.
	shuffled := slices.Clone(names)
	for range 20 {
		shuffled = append(shuffled[1:], shuffled[0])
		if got := build(shuffled).Types(); !slices.Equal(got, want) {
			t.Fatalf("for registration order %v: got %v; want %v",
				shuffled, got, want)
		}
	}
}

func TestRegister_Panics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fn   func()
	}{
		{
			name: "empty name",
			fn: func() {
				r := diff.NewRegistry[struct{}]()
				diff.Register[struct{}, doc](r, "", noop{},
					diff.WithRootMeta())
			},
		},
		{
			name: "reserved name",
			fn: func() {
				r := diff.NewRegistry[struct{}]()
				diff.Register[struct{}, doc](r, diff.TypeShare, noop{},
					diff.WithRootMeta())
			},
		},
		{
			name: "nil handler",
			fn: func() {
				r := diff.NewRegistry[struct{}]()
				diff.Register[struct{}, doc](r, "asset", nil,
					diff.WithRootMeta())
			},
		},
		{
			name: "duplicate name",
			fn: func() {
				r := diff.NewRegistry[struct{}]()
				diff.Register[struct{}, doc](r, "asset", noop{},
					diff.WithRootMeta())
				diff.Register[struct{}, doc](r, "asset", noop{},
					diff.WithRootMeta())
			},
		},
		{
			name: "missing ownership mode",
			fn: func() {
				r := diff.NewRegistry[struct{}]()
				diff.Register[struct{}, doc](r, "asset", noop{})
			},
		},
		{
			name: "conflicting ownership modes",
			fn: func() {
				r := diff.NewRegistry[struct{}]()
				diff.Register[struct{}, doc](r, "asset", noop{},
					diff.WithRootMeta(), diff.WithOwner("other", "other_id"))
			},
		},
		{
			name: "unknown parent",
			fn: func() {
				r := diff.NewRegistry[struct{}]()
				diff.Register[struct{}, doc](r, "asset", noop{},
					diff.WithRootMeta(), diff.WithParents("missing"))
				r.Types()
			},
		},
		{
			name: "dependency cycle",
			fn: func() {
				r := diff.NewRegistry[struct{}]()
				diff.Register[struct{}, doc](r, "a", noop{},
					diff.WithRootMeta(), diff.WithParents("b"))
				diff.Register[struct{}, doc](r, "b", noop{},
					diff.WithRootMeta(), diff.WithParents("a"))
				r.Types()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Error("should have panicked")
				}
			}()
			tt.fn()
		})
	}
}
