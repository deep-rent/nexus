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

package telemetry

import (
	"context"

	"github.com/deep-rent/nexus/app"
)

// Component adapts the telemetry lifecycle to an [app.Component]: it
// signals readiness, waits for the shutdown, and then flushes and stops the
// providers within the application's shutdown budget.
//
// Place it in the first stage of [app.RunStages], so that the reverse-order
// shutdown flushes telemetry only after every emitting component has
// stopped:
//
//	app.RunStages([]app.Stage{
//		{app.Named("telemetry", tel.Component())},
//		{app.Named("server", server)},
//	})
func (t *Telemetry) Component() app.Component {
	return func(ctx context.Context) error {
		app.Ready(ctx)
		<-ctx.Done()

		// Detach from the canceled context so that the final flush can still
		// reach the collector, but bound it by the shutdown budget.
		sctx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			app.ShutdownTimeout(ctx),
		)
		defer cancel()

		return t.Shutdown(sctx)
	}
}
