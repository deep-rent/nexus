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

package throttle

import (
	"net/http"
	"time"

	"golang.org/x/time/rate"

	"github.com/deep-rent/nexus/sys/metrics"
)

// Default values applied by [New] for the optional [Config] fields.
const (
	// DefaultRate is the sustained rate, in tokens per second, at which a
	// drained allowance recovers.
	DefaultRate = rate.Limit(1)
	// DefaultBurst is the number of tokens each key may hold.
	DefaultBurst = 60
)

// Config carries the tunable settings for a [Throttle]. Zero values are
// replaced with the package defaults by [New].
type Config struct {
	// Rate is the sustained rate, in tokens per second, at which a drained
	// allowance recovers. Defaults to [DefaultRate].
	Rate rate.Limit
	// Burst is the number of tokens each key may hold. It caps how many
	// actions can be taken back to back before the rate takes over. Defaults
	// to [DefaultBurst].
	Burst int
	// Key derives the bucket key from a request for [Throttle.Middleware]. It
	// defaults to the remote address of the TCP connection, with the port
	// stripped, so that all connections from one host share a bucket.
	//
	// Deployments behind a trusted reverse proxy or load balancer should
	// override this to read the forwarded client address, for example from
	// the X-Forwarded-For header. Never trust such headers unless an upstream
	// proxy is guaranteed to overwrite them: a spoofed value lets an attacker
	// pick a fresh bucket for every request and bypass limiting entirely.
	//
	// It is only consulted by [Throttle.Middleware]; the keyed methods take
	// the key directly.
	Key func(*http.Request) string
	// Clock overrides the time source. This is primarily useful for
	// deterministic testing. Defaults to [time.Now].
	Clock func() time.Time
	// Name is the value of the "name" tag on the recorded counters,
	// keeping multiple instances apart in a metrics backend. Defaults to
	// the empty string.
	Name string
	// Registry records the [Decisions] and [Penalties] counters. Defaults
	// to [metrics.DefaultRegistry].
	Registry *metrics.Registry
}
