package pointer

import "reflect"

// Deref follows pointers until it reaches a non-pointer, allocating if nil.
// If an un-settable nil pointer is encountered (e.g., a nil pointer inside
// an unexported field of a struct), the function stops dereferencing and
// returns the non-settable nil pointer to prevent a panic.
func Deref(rv reflect.Value) reflect.Value {
	// Loop through multi-level pointers to handle cases like **int.
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			if !rv.CanSet() {
				break
			}
			Alloc(rv)
		}
		rv = rv.Elem()
	}
	return rv
}

// Alloc allocates a new value for a nil pointer.
func Alloc(rv reflect.Value) {
	rv.Set(reflect.New(rv.Type().Elem()))
}
