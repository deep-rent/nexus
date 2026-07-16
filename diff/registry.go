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

package diff

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"slices"
	"uuid"

	"github.com/deep-rent/nexus/internal/graph"
	"github.com/deep-rent/nexus/valid"
)

// TypeShare is the reserved entity type implementing personal-document
// grants. Register a store-backed handler for it via [RegisterShares] to
// enable sharing.
const TypeShare = "share"

// typeConfig holds the relationship metadata of one entity type.
type typeConfig struct {
	parents  []string
	root     bool
	owner    string // ownership parent type; empty for roots
	ownerVia string // JSON field referencing the ownership parent
}

// TypeOption configures a single entity type registration.
type TypeOption func(*typeConfig)

// WithParents declares that the entity type references the given parent
// types through client-side foreign keys. Parents are upserted before, and
// deleted after, this type in the patch feed.
func WithParents(types ...string) TypeOption {
	return func(c *typeConfig) {
		c.parents = append(c.parents, types...)
	}
}

// WithRootMeta marks the type as a root: its payloads carry the identifying
// [Meta] envelope (id, user_id, and optional team_id).
func WithRootMeta() TypeOption {
	return func(c *typeConfig) {
		c.root = true
	}
}

// WithOwner marks the type as a child owned by the given parent type. The
// via argument names the JSON field in the child payload that references
// its parent document. Ownership chains resolve transitively to a root.
// The parent is implicitly part of the dependency graph, as if declared
// with [WithParents].
func WithOwner(parent, via string) TypeOption {
	return func(c *typeConfig) {
		c.owner = parent
		c.ownerVia = via
	}
}

// entry describes one registered entity type.
type entry[Tx any] struct {
	typeConfig
	name    string
	handler Handler[Tx]
	check   func(data jsontext.Value) valid.Error
}

// Registry maps entity type names to their handlers and relationship
// metadata. Populate it with [Register] and pass it to [New].
type Registry[Tx any] struct {
	entries map[string]*entry[Tx]
	sorted  []string // memoized topological order (parents first)
}

// NewRegistry initializes an empty type registry.
func NewRegistry[Tx any]() *Registry[Tx] {
	return &Registry[Tx]{entries: make(map[string]*entry[Tx])}
}

// Register binds an entity type name to its handler. The type parameter T
// is the document model; incoming payloads are unmarshaled into T and, if T
// implements [valid.Validatable], validated before ingestion. Exactly one
// of [WithRootMeta] or [WithOwner] must be provided.
//
// Register panics if the name is empty, reserved, or already taken
// (programmer error).
func Register[Tx any, T any](
	r *Registry[Tx],
	name string,
	h Handler[Tx],
	opts ...TypeOption,
) {
	if name == "" {
		panic("entity type name is required")
	}
	if name == TypeShare {
		panic("entity type name is reserved, use RegisterShares")
	}
	register[Tx, T](r, name, h, opts...)
}

// RegisterShares enables personal-document grants by binding the reserved
// [TypeShare] entity type to a store-backed handler (see
// driver/postgres.Store.Shares).
func RegisterShares[Tx any](r *Registry[Tx], h Handler[Tx]) {
	register[Tx, Share](r, TypeShare, h, WithRootMeta())
}

// Share is the document model of the reserved [TypeShare] entity type: it
// grants a team access to the owner's personal documents.
type Share struct {
	// ID is the share identifier (UUIDv7).
	ID uuid.UUID `json:"id"`
	// UserID is the granting owner; it must equal the authenticated user.
	UserID uuid.UUID `json:"user_id"`
	// TeamID is the team being granted access.
	TeamID *uuid.UUID `json:"team_id"`
}

// Validate implements the [valid.Validatable] interface.
func (s *Share) Validate(v *valid.Validator) {
	if s.TeamID == nil || *s.TeamID == uuid.Nil() {
		v.Fail("team_id", "must not be empty")
	}
}

var _ valid.Validatable = (*Share)(nil)

func register[Tx any, T any](
	r *Registry[Tx],
	name string,
	h Handler[Tx],
	opts ...TypeOption,
) {
	if h == nil {
		panic("handler is required")
	}
	if _, exists := r.entries[name]; exists {
		panic(fmt.Sprintf("entity type %q is already registered", name))
	}

	e := &entry[Tx]{name: name, handler: h}
	for _, opt := range opts {
		opt(&e.typeConfig)
	}

	if e.root == (e.owner != "") {
		panic(fmt.Sprintf(
			"entity type %q needs exactly one of WithRootMeta or WithOwner",
			name,
		))
	}

	e.check = func(data jsontext.Value) valid.Error {
		var v T
		if err := json.Unmarshal(data, &v); err != nil {
			return valid.Error{"data": {"must be a well-formed document"}}
		}
		return valid.Test(&v)
	}

	r.entries[name] = e
	r.sorted = nil
}

// order returns the deterministic topological order of all registered types
// (parents first). It memoizes its result and panics on dependency cycles
// or references to unregistered types (programmer error, surfaced by [New]).
func (r *Registry[Tx]) order() []string {
	if r.sorted != nil {
		return r.sorted
	}

	names := make([]string, 0, len(r.entries))
	for name := range r.entries {
		names = append(names, name)
	}
	slices.Sort(names)

	// Feeding nodes and edges in sorted order makes the topological order a
	// deterministic function of the registered set, independent of
	// registration order.
	g := graph.New[string]()
	for _, name := range names {
		g.AddNode(name)
	}
	for _, name := range names {
		e := r.entries[name]
		refs := slices.Clone(e.parents)
		if e.owner != "" {
			refs = append(refs, e.owner)
		}
		for _, parent := range refs {
			if _, exists := r.entries[parent]; !exists {
				panic(fmt.Sprintf(
					"entity type %q references unregistered type %q",
					name, parent,
				))
			}
			if parent != name {
				g.AddEdge(name, parent)
			}
		}
	}

	sorted, err := g.Sort()
	if err != nil {
		panic(err)
	}

	r.sorted = sorted
	return sorted
}

// Types returns all registered entity type names in their deterministic
// topological order (parents first). It panics on dependency cycles or
// references to unregistered types.
func (r *Registry[Tx]) Types() []string {
	return slices.Clone(r.order())
}

// lookup returns the entry registered under the given type name.
func (r *Registry[Tx]) lookup(name string) (*entry[Tx], bool) {
	e, ok := r.entries[name]
	return e, ok
}
