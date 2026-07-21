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

// Package valid provides utility functions for validating common formats and
// data types.
//
// The valid package offers a comprehensive suite of validation tools designed
// to simplify data integrity checks in Go applications. It includes standalone
// predicate functions for format verification and a stateful [Validator] for
// aggregating errors across complex, nested structures.
//
// Note: By package convention, all character class predicates return true for
// an empty string, unless otherwise noted.
//
// # Usage
//
// You can use standalone functions for simple checks or the [Validator] type
// for struct validation.
//
// Standalone Validation:
//
// Direct check of a single value using predicate functions.
//
// Example:
//
//	isValid := valid.Email("user@example.com")
//
// Struct Validation:
//
// Implementing the [Validatable] interface to perform complex checks.
//
// Example:
//
//	type User struct {
//		Email string
//		Age   int
//	}
//
//	func (u *User) Validate(v *valid.Validator) {
//		v.Email("email", u.Email)
//		v.BetweenInt("age", u.Age, 18, 99)
//	}
//
//	usr := &User{Email: "user@example.com", Age: 25}
//	err := valid.Test(usr)
//	if err != nil {
//		// Handle validation errors
//	}
package valid
