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

package app

import (
	"errors"
	"fmt"
	"strconv"
)

var (
	// ErrShutdownTimeout indicates that one or more [Component] functions did
	// not return within the configured shutdown timeout. See [WithTimeout].
	ErrShutdownTimeout = errors.New("shutdown timed out")

	// ErrStartTimeout indicates that a [Stage] did not signal readiness within
	// the configured startup timeout. See [Ready] and [WithStartTimeout].
	ErrStartTimeout = errors.New("startup timed out")

	// ErrNoComponents indicates that no [Component] was passed to the runner.
	ErrNoComponents = errors.New("no components to run")

	// ErrNilComponent indicates that a nil [Component] was passed to the
	// runner.
	ErrNilComponent = errors.New("nil component")
)

// PanicError wraps a value recovered from a panicking [Component]. The runner
// converts panics into errors so that a single misbehaving component cannot
// bring down the process without the remaining components being shut down
// gracefully.
type PanicError struct {
	// Value is the value passed to panic.
	Value any
	// Stack is the stack trace captured at the point of recovery.
	Stack []byte
}

// Error implements the error interface.
func (e *PanicError) Error() string {
	return fmt.Sprintf("panic: %v", e.Value)
}

// Unwrap returns the recovered value if it is itself an error, allowing
// [errors.Is] and [errors.As] to inspect the original cause. It returns nil
// otherwise.
func (e *PanicError) Unwrap() error {
	err, _ := e.Value.(error)
	return err
}

// ComponentError attributes an error to a named [Component]. It is produced by
// components wrapped in [Named].
type ComponentError struct {
	// Name is the name given to the component via [Named].
	Name string
	// Err is the error returned by the component.
	Err error
}

// Error implements the [error] interface.
func (e *ComponentError) Error() string {
	return "component " + strconv.Quote(e.Name) + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ComponentError) Unwrap() error { return e.Err }

var _ error = (*ComponentError)(nil)
