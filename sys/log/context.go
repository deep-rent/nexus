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

package log

import "context"

// levelKey is the context key under which a level override is stored.
type levelKey struct{}

// SetLevel returns a context carrying a level override. For records
// logged under the returned context, the JSON sink replaces its
// configured threshold with the given level, in either direction: the
// override can force debug output for a single request as well as quiet a
// known-noisy code path.
//
//	ctx = log.SetLevel(ctx, log.LevelDebug)
func SetLevel(ctx context.Context, level Level) context.Context {
	return context.WithValue(ctx, levelKey{}, level)
}

// GetLevel returns the level override carried by ctx, if any. It is
// exported for use by custom [Sink] implementations, which should honor
// the override in their Enabled method.
func GetLevel(ctx context.Context) (Level, bool) {
	level, ok := ctx.Value(levelKey{}).(Level)
	return level, ok
}
