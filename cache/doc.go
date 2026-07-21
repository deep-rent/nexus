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

// Package cache provides a generic, auto-refreshing in-memory cache for a
// resource fetched from a URL.
//
// The core of the package is the [Controller], a [schedule.Tick] that
// periodically fetches a remote resource, parses it, and caches it in memory.
//
// # Refresh interval
//
// The interval is derived from the resource's caching headers (Cache-Control,
// Expires) and clamped to the range configured via [WithMinInterval] and
// [WithMaxInterval]. Failed refreshes do not fall back to that interval;
// instead they back off exponentially from [DefaultRetryDelay], so a transient
// outage is recovered from in seconds rather than after a full refresh cycle.
// See [WithBackoff].
//
// Conditional requests using ETag and Last-Modified reduce bandwidth: a
// resource that has not changed is answered with 304 and the cached value is
// retained.
//
// # Usage
//
// A typical use case involves creating a [schedule.Scheduler], defining a
// [Mapper] function to parse the HTTP response, creating and configuring a
// [Controller], and then dispatching it to run in the background.
//
// Example:
//
//	type Resource struct {
//		// fields for the parsed data
//	}
//
//	// 1. Create a scheduler to manage the refresh ticks.
//	sched := schedule.New(context.Background())
//	defer sched.Shutdown()
//
//	// 2. Define a mapper to parse the response body into your target type.
//	mapper := func(r *cache.Response) (Resource, error) {
//		var data Resource
//		err := json.Unmarshal(r.Body, &data)
//		return data, err
//	}
//
//	// 3. Create and configure the cache controller.
//	ctrl := cache.NewController(
//		"https://api.example.com/resource",
//		mapper,
//		cache.WithMinInterval(5*time.Minute),
//	)
//
//	// 4. Dispatch the controller to start fetching in the background.
//	sched.Dispatch(ctrl)
//
//	// 5. Wait for the first successful fetch.
//	<-ctrl.Ready()
//
//	// 6. Get the cached data.
//	if data, ok := ctrl.Get(); ok {
//		fmt.Printf("Successfully fetched and cached data: %+v\n", data)
//	}
package cache
