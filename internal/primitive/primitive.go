// Package primitive provides utility functions for working with Go's primitive
// types using reflection. It allows for checking if a reflect.Kind is a
// primitive and parsing strings into a reflect.Value of a primitive type.
package primitive

import (
	"fmt"
	"reflect"
	"strconv"
)

// Parse attempts to convert string v to the type expected by rv and sets it.
//
// It supports all primitive types covered by the Is function. Other types
// will result in an error. The caller must ensure that rv is settable, or
// else Parse will panic.
func Parse(rv reflect.Value, v string) error {
	switch kind := rv.Kind(); kind {
	case reflect.Bool:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("%q is not a bool", v)
		}
		rv.SetBool(b)
	case reflect.String:
		rv.SetString(v)
	case
		reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64:
		b := rv.Type().Bits()
		i, err := strconv.ParseInt(v, 10, b)
		if err != nil {
			return fmt.Errorf("%q is not an int%d", v, b)
		}
		rv.SetInt(i)
	case
		reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64:
		b := rv.Type().Bits()
		u, err := strconv.ParseUint(v, 10, b)
		if err != nil {
			return fmt.Errorf("%q is not a uint%d", v, b)
		}
		rv.SetUint(u)
	case reflect.Float32, reflect.Float64:
		b := rv.Type().Bits()
		f, err := strconv.ParseFloat(v, b)
		if err != nil {
			return fmt.Errorf("%q is not a float%d", v, b)
		}
		rv.SetFloat(f)
	case reflect.Complex64, reflect.Complex128:
		b := rv.Type().Bits()
		c, err := strconv.ParseComplex(v, b)
		if err != nil {
			return fmt.Errorf("%q is not a complex%d", v, b)
		}
		rv.SetComplex(c)
	default:
		return fmt.Errorf("unsupported type: %s", kind)
	}
	return nil
}
