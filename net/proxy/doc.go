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

// Package proxy provides a configurable reverse proxy handler.
//

// Package proxy constructs an [httputil.ReverseProxy], starting with sensible
// defaults, integrating a reusable buffer pool, structured logging, and robust
// error handling via a functional options API.
//
// # Usage
//
// Create a new proxy handler by providing a target URL and optional
// configuration functions.
//
// Example:
//
//	target, _ := url.Parse("https://backend.internal")
//	proxyHandler := proxy.NewHandler(target,
//	    proxy.WithFlushInterval(100*time.Millisecond),
//	    proxy.WithMaxBufferSize(512<<10),
//	)
//
//	http.ListenAndServe(":8080", proxyHandler)
package proxy
