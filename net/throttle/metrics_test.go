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

package throttle_test

import (
	"testing"

	"github.com/deep-rent/nexus/sys/metrics"
	"github.com/deep-rent/nexus/net/throttle"
)

// decisionCounts collects the decision counter grouped by the allowed tag,
// returning the instance name tag alongside.
func decisionCounts(
	t *testing.T,
	reg *metrics.Registry,
) (counts map[string]uint64, name string) {
	t.Helper()

	counts = make(map[string]uint64)
	for _, s := range reg.Snapshot().Metrics {
		if s.Name != throttle.Decisions {
			continue
		}
		counts[s.Tags["allowed"]] += uint64(s.Value)
		name = s.Tags["name"]
	}
	return counts, name
}

func TestThrottle_CountsDecisions(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	th := throttle.New(throttle.Config{
		Rate:     1,
		Burst:    2,
		Name:     "login",
		Registry: reg,
	})

	// The burst of 2 admits two spends; the third is rejected.
	for range 2 {
		if !th.Allow("alice") {
			t.Fatal("allow: got false; want true")
		}
	}
	if th.Allow("alice") {
		t.Fatal("allow: got true; want false")
	}

	counts, name := decisionCounts(t, reg)
	if got := counts["true"]; got != 2 {
		t.Errorf("allowed: got %d; want 2", got)
	}
	if got := counts["false"]; got != 1 {
		t.Errorf("rejected: got %d; want 1", got)
	}
	if name != "login" {
		t.Errorf("name tag: got %q; want %q", name, "login")
	}
}

func TestThrottle_CountsPenalties(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	th := throttle.New(throttle.Config{Registry: reg})

	th.Penalize("alice", 10)
	th.Penalize("alice", 0) // A non-positive charge is not counted.

	var penalties uint64
	for _, s := range reg.Snapshot().Metrics {
		if s.Name == throttle.Penalties {
			penalties += uint64(s.Value)
		}
	}
	if penalties != 1 {
		t.Errorf("penalties: got %d; want 1", penalties)
	}
}
