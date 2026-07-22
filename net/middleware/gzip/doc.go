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

// Package gzip provides an HTTP middleware for compressing response bodies.
//
// It compresses response payloads with the gzip algorithm for clients that
// support it (indicated by the "Accept-Encoding" request header) and
// automatically adds the "Content-Encoding: gzip" header. Responses that
// already carry a Content-Encoding, bodiless statuses (204, 205, 304), and
// HEAD requests are passed through untouched, and MIME types on the
// exclusion list (media, fonts, and archives by default) are skipped.
//
// # Usage
//
// The middleware is designed to be efficient. It pools [gzip.Writer]
// instances to reduce memory allocations.
//
// Handlers should set Content-Type before the first write: the compression
// decision is made when the headers are written, and without an explicit
// type the standard library would sniff the compressed bytes and mislabel
// the response.
//
// Example:
//
//	// Create the final handler.
//	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	  w.Header().Set("Content-Type", "text/plain")
//	  w.Write([]byte("This is a long string that will be compressed."))
//	})
//
//	// Create a gzip middleware pipe with the highest level of compression.
//	pipe := gzip.New(
//	  gzip.WithCompressionLevel(gzip.BestCompression),
//	  gzip.WithExcludeMimeTypes("application/vnd.apache.parquet"),
//	)
//
//	// Apply the middleware as one of the first layers.
//	chainedHandler := middleware.Chain(handler, pipe)
//
//	http.ListenAndServe(":8080", chainedHandler)
package gzip
