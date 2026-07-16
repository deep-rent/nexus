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

func TestRegistry_Models_Deterministic(t *testing.T) {
	t.Parallel()

	names := []string{"asset", "address", "contract", "party", "sector"}

	build := func(order []string) *diff.Registry[struct{}] {
		r := diff.NewRegistry[struct{}]()
		for _, name := range order {
			switch name {
			case "asset":
				r.Register[doc](name, noop{},
					diff.Root(), diff.Parents("address"))
			case "contract":
				r.Register[doc](name, noop{},
					diff.Owner("asset", "asset_id"))
			case "address":
				r.Register[doc](name, noop{},
					diff.Root())
			default:
				r.Register[doc](name, noop{},
					diff.Root())
			}
		}
		return r
	}

	want := build(names).Models()

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
		if got := build(shuffled).Models(); !slices.Equal(got, want) {
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
				r.Register[doc]("", noop{},
					diff.Root())
			},
		},
		{
			name: "reserved name",
			fn: func() {
				r := diff.NewRegistry[struct{}]()
				r.Register[doc](diff.ModelShare, noop{},
					diff.Root())
			},
		},
		{
			name: "nil handler",
			fn: func() {
				r := diff.NewRegistry[struct{}]()
				r.Register[doc]("asset", nil,
					diff.Root())
			},
		},
		{
			name: "duplicate name",
			fn: func() {
				r := diff.NewRegistry[struct{}]()
				r.Register[doc]("asset", noop{},
					diff.Root())
				r.Register[doc]("asset", noop{},
					diff.Root())
			},
		},
		{
			name: "missing ownership mode",
			fn: func() {
				r := diff.NewRegistry[struct{}]()
				r.Register[doc]("asset", noop{})
			},
		},
		{
			name: "conflicting ownership modes",
			fn: func() {
				r := diff.NewRegistry[struct{}]()
				r.Register[doc]("asset", noop{},
					diff.Root(), diff.Owner("other", "other_id"))
			},
		},
		{
			name: "unknown parent",
			fn: func() {
				r := diff.NewRegistry[struct{}]()
				r.Register[doc]("asset", noop{},
					diff.Root(), diff.Parents("missing"))
				r.Models()
			},
		},
		{
			name: "dependency cycle",
			fn: func() {
				r := diff.NewRegistry[struct{}]()
				r.Register[doc]("a", noop{},
					diff.Root(), diff.Parents("b"))
				r.Register[doc]("b", noop{},
					diff.Root(), diff.Parents("a"))
				r.Models()
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
