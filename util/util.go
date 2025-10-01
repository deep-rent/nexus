package util

import "fmt"

// Zero returns the zero value of type T.
func Zero[T any]() T {
	var zero T
	return zero
}

// Conv attempts to cast the given value to type T.
func Conv[T any](v any) (T, error) {
	vt, ok := v.(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("expected %T, got %T", zero, v)
	}
	return vt, nil
}

func Keys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func Vals[K comparable, V any](m map[K]V) []V {
	vals := make([]V, 0, len(m))
	for _, v := range m {
		vals = append(vals, v)
	}
	return vals
}

// Concat takes a slice and a variable number of values, and returns a new slice
// containing all the elements without modifying the original.
func Concat[T any](src []T, add ...T) []T {
	n := len(src)
	k := len(add)
	res := make([]T, n+k)
	copy(res, src)
	copy(res[n:], add)
	return res
}
