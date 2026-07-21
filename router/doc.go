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

// Package router provides a lightweight, JSON-centric wrapper around Go's
// native [http.ServeMux].
//
// It simplifies building JSON APIs by offering a consolidated "Exchange" object
// for handling requests and responses, standardized error formatting, and a
// middleware chaining mechanism.
//
// # Basic Usage
//
// 1. Setup the router with options:
//
// Example:
//
//	logger := log.New()
//	r := router.New(
//	  router.WithLogger(logger),
//	  router.WithMiddleware(router.Log(logger)),
//	)
//
// 2. Define a handler:
//
// Example:
//
//	r.HandleFunc("POST /users", func(e *router.Exchange) error {
//	  var req CreateUserRequest
//	  if err := e.BindJSON(&req); err != nil {
//	    return err
//	  }
//	  return e.JSON(http.StatusCreated, UserResponse{ID: "123"})
//	})
//
// 3. Start the server:
//
// Example:
//
//	http.ListenAndServe(":8080", r)
package router
