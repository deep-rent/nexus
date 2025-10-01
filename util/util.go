package util

// Zero returns the zero value of type T.
func Zero[T any]() T {
	var zero T
	return zero
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
