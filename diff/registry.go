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

// ModelShare is the reserved model implementing personal-document grants.
// Register a store-backed handler for it via [Registry.RegisterShares] to
// enable sharing.
const ModelShare = "share"

// modelConfig holds the structural constraints of one registered model.
type modelConfig struct {
	parents  []string
	root     bool
	owner    string // ownership parent model; empty for roots
	ownerVia string // JSON field referencing the ownership parent
}

// Constraint declares a structural property of a registered model, such as
// its position in the ownership hierarchy or its foreign key dependencies.
type Constraint func(*modelConfig)

// Parents declares that the model references the given parent models
// through client-side foreign keys. Parents are upserted before, and
// deleted after, this model in the patch feed.
func Parents(models ...string) Constraint {
	return func(c *modelConfig) {
		c.parents = append(c.parents, models...)
	}
}

// Root marks the model as a hierarchy root: its payloads carry the
// identifying [Meta] envelope (id, user_id, and optional team_id).
func Root() Constraint {
	return func(c *modelConfig) {
		c.root = true
	}
}

// Owner marks the model as a child owned by the given parent model. The
// via argument names the JSON field in the child payload that references
// its parent document. Ownership chains resolve transitively to a root.
// The parent is implicitly part of the dependency graph, as if declared
// with [Parents].
func Owner(parent, via string) Constraint {
	return func(c *modelConfig) {
		c.owner = parent
		c.ownerVia = via
	}
}

// entry describes one registered model.
type entry[Tx any] struct {
	modelConfig
	name    string
	handler Handler[Tx]
	check   func(data jsontext.Value) valid.Error
}

// Registry maps model names to their handlers and structural constraints.
// Populate it with [Registry.Register] and pass it to [New].
type Registry[Tx any] struct {
	entries map[string]*entry[Tx]
	sorted  []string // memoized topological order (parents first)
}

// NewRegistry initializes an empty model registry.
func NewRegistry[Tx any]() *Registry[Tx] {
	return &Registry[Tx]{entries: make(map[string]*entry[Tx])}
}

// Register binds a model name to its handler. The type parameter T is the
// document model; incoming payloads are unmarshaled into T and, if T
// implements [valid.Validatable], validated before ingestion. Exactly one
// of [Root] or [Owner] must be provided.
//
// Register panics if the name is empty, reserved, or already taken
// (programmer error).
func (r *Registry[Tx]) Register[T any](
	name string,
	h Handler[Tx],
	constraints ...Constraint,
) {
	if name == "" {
		panic("model name is required")
	}
	if name == ModelShare {
		panic("model name is reserved")
	}
	register[Tx, T](r, name, h, constraints...)
}

// RegisterShares enables personal-document grants by binding the reserved
// [ModelShare] model to a store-backed handler (see
// driver/postgres.Store.Shares).
func (r *Registry[Tx]) RegisterShares(h Handler[Tx]) {
	register[Tx, Share](r, ModelShare, h, Root())
}

// Share is the document model of the reserved [ModelShare] entity: it
// grants a team access to the owner's personal documents.
type Share struct {
	// ID is the share identifier (UUIDv7).
	ID uuid.UUID `json:"id"`
	// UserID is the granting owner; it must equal the authenticated user.
	UserID string `json:"user_id"`
	// TeamID is the team being granted access.
	TeamID string `json:"team_id"`
}

// Validate implements the [valid.Validatable] interface.
func (s *Share) Validate(v *valid.Validator) {
	if !valid.UUID(s.TeamID) {
		v.Fail("team_id", "must be a valid UUID")
	}
}

var _ valid.Validatable = (*Share)(nil)

func register[Tx any, T any](
	r *Registry[Tx],
	name string,
	h Handler[Tx],
	constraints ...Constraint,
) {
	if h == nil {
		panic("handler is required")
	}
	if _, exists := r.entries[name]; exists {
		panic(fmt.Sprintf("model %q is already registered", name))
	}

	e := &entry[Tx]{name: name, handler: h}
	for _, constrain := range constraints {
		constrain(&e.modelConfig)
	}

	if e.root == (e.owner != "") {
		panic(fmt.Sprintf(
			"model %q needs exactly one of Root or Owner", name,
		))
	}
	if e.owner == name {
		panic(fmt.Sprintf("model %q cannot own itself", name))
	}
	if slices.Contains(e.parents, name) {
		panic(fmt.Sprintf("model %q cannot be its own parent", name))
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

// order returns the canonical topological order of all registered models
// (parents first). It memoizes its result and panics on dependency cycles
// or references to unregistered models (programmer error, surfaced by
// [New]).
func (r *Registry[Tx]) order() []string {
	if r.sorted != nil {
		return r.sorted
	}

	g := graph.New[string]()
	for name, e := range r.entries {
		g.AddNode(name)
		refs := slices.Clone(e.parents)
		if e.owner != "" {
			refs = append(refs, e.owner)
		}
		for _, parent := range refs {
			if _, exists := r.entries[parent]; !exists {
				panic(fmt.Sprintf(
					"model %q references unregistered model %q",
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

// Models returns all registered model names in their canonical topological
// order (parents first). It panics on dependency cycles or references to
// unregistered models.
func (r *Registry[Tx]) Models() []string {
	return slices.Clone(r.order())
}

// checkHandlers cross-checks each handler that implements [Describer]
// against its registry entry, panicking on a mismatch. This catches, at
// construction time, a handler configured with a different model name or
// parent reference than the entry it is registered under — a
// misconfiguration that would otherwise silently corrupt the patch feed.
func (r *Registry[Tx]) checkHandlers() {
	for name, e := range r.entries {
		d, ok := e.handler.(Describer)
		if !ok {
			continue
		}
		if got := d.Model(); got != name {
			panic(fmt.Sprintf(
				"handler for %q reports model %q; names must match",
				name, got,
			))
		}
		via, hasParent := d.Parent()
		if hasParent != (e.owner != "") || via != e.ownerVia {
			panic(fmt.Sprintf(
				"handler for %q references parent field %q; "+
					"registry declares %q",
				name, via, e.ownerVia,
			))
		}
	}
}

// lookup returns the entry registered under the given model name.
func (r *Registry[Tx]) lookup(name string) (*entry[Tx], bool) {
	e, ok := r.entries[name]
	return e, ok
}
