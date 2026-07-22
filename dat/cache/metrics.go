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

package cache

import (
	"github.com/deep-rent/nexus/sys/metrics"
)

// Refreshes is the name of the counter recording refresh cycles, tagged
// with the resource URL and an outcome of "updated", "unchanged", or
// "error".
const Refreshes = "cache_refreshes_total"

// stats holds the per-outcome refresh counters, resolved once at
// construction.
type stats struct {
	updated   *metrics.Counter
	unchanged *metrics.Counter
	failed    *metrics.Counter
}

// newStats resolves the refresh counters from the given registry.
func newStats(reg *metrics.Registry, url string) stats {
	outcome := func(o string) *metrics.Counter {
		return reg.Counter(Refreshes,
			metrics.T("url", url),
			metrics.T("outcome", o),
		)
	}
	return stats{
		updated:   outcome("updated"),
		unchanged: outcome("unchanged"),
		failed:    outcome("error"),
	}
}
