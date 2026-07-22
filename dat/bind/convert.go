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

package bind

import (
	"encoding"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/deep-rent/nexus/std/pointer"
)

// setValues assigns values to a [reflect.Value] based on its type.
func setValues(rv reflect.Value, vals []string, f *Flags) error {
	rv = pointer.Deref(rv)
	if rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() != reflect.Uint8 {
		return setSlice(rv, vals, f)
	}

	v := vals[0] // Primitive types only take the first value

	switch rv.Type() {
	case typeTime:
		return setTime(rv, v, f)
	case typeDuration:
		return setDuration(rv, v, f)
	case typeLocation:
		return setLocation(rv, v)
	case typeURL:
		return setURL(rv, v)
	}

	if u, ok := asTextUnmarshaler(rv); ok {
		// Use the standard unmarshaler if available.
		return u.UnmarshalText([]byte(v))
	}

	return setOther(rv, v, f)
}

// setOther handles all "regular" (primitive and []byte) types by delegating to
// the appropriate parsing logic based on the reflective kind.
func setOther(rv reflect.Value, v string, f *Flags) error {
	switch kind := rv.Kind(); kind {
	case reflect.Slice:
		return setBytes(rv, v, f)
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
		fval, err := strconv.ParseFloat(v, b)
		if err != nil {
			return fmt.Errorf("%q is not a float%d", v, b)
		}
		rv.SetFloat(fval)
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

// setTime parses and sets a [time.Time] value based on the provided format and
// unit options.
func setTime(rv reflect.Value, v string, f *Flags) error {
	var t time.Time
	var err error
	switch format := f.Format; format {
	case "unix":
		var i int64
		i, err = strconv.ParseInt(v, 10, 64)
		if err == nil {
			switch unit := f.Unit; unit {
			case "s", "":
				t = time.Unix(i, 0)
			case "ms":
				t = time.UnixMilli(i)
			case "us", "μs":
				t = time.UnixMicro(i)
			default:
				err = fmt.Errorf("invalid time unit: %q", unit)
			}
		}
	case "dateTime":
		t, err = time.Parse(time.DateTime, v)
	case "date":
		t, err = time.Parse(time.DateOnly, v)
	case "time":
		t, err = time.Parse(time.TimeOnly, v)
	case "":
		format = time.RFC3339
		fallthrough
	default:
		t, err = time.Parse(format, v)
	}
	if err != nil {
		return err
	}
	rv.Set(reflect.ValueOf(t))
	return nil
}

// setDuration parses and sets a [time.Duration] value based on the provided
// unit option.
func setDuration(rv reflect.Value, v string, f *Flags) error {
	var d time.Duration
	var err error
	if unit := f.Unit; unit == "" {
		d, err = time.ParseDuration(v)
	} else {
		var i int64
		i, err = strconv.ParseInt(v, 10, 64)
		if err == nil {
			switch unit {
			case "ns":
				d = time.Duration(i)
			case "us", "μs":
				d = time.Duration(i) * time.Microsecond
			case "ms":
				d = time.Duration(i) * time.Millisecond
			case "s":
				d = time.Duration(i) * time.Second
			case "m":
				d = time.Duration(i) * time.Minute
			case "h":
				d = time.Duration(i) * time.Hour
			default:
				err = fmt.Errorf("invalid duration unit: %q", unit)
			}
		}
	}
	if err != nil {
		return err
	}
	rv.SetInt(int64(d))
	return nil
}

// setLocation parses and sets a [time.Location] value.
func setLocation(rv reflect.Value, v string) error {
	loc, err := time.LoadLocation(v)
	if err != nil {
		return err
	}
	rv.Set(reflect.ValueOf(*loc))
	return nil
}

// setURL parses and sets a [url.URL] value.
func setURL(rv reflect.Value, v string) error {
	u, err := url.Parse(v)
	if err != nil {
		return err
	}
	rv.Set(reflect.ValueOf(*u))
	return nil
}

// setBytes parses and sets a []byte slice value, supporting special
// encoding formats like hex, base32, and base64.
func setBytes(rv reflect.Value, v string, f *Flags) error {
	var b []byte
	var err error
	switch f.Format {
	case "":
		b = []byte(v)
	case "hex":
		b, err = hex.DecodeString(v)
	case "base32":
		b, err = base32.StdEncoding.DecodeString(v)
	case "base64":
		b, err = base64.StdEncoding.DecodeString(v)
	default:
		return fmt.Errorf("unsupported format for []byte: %q", f.Format)
	}
	if err != nil {
		return err
	}
	rv.SetBytes(b)
	return nil
}

// setSlice parses and sets a slice value by parsing each element.
// If exactly one value is provided and a delimiter (split flag) is present,
// it will optionally split that single string to maintain backwards
// compatibility
// with environment variable formats.
func setSlice(rv reflect.Value, vals []string, f *Flags) error {
	if len(vals) == 1 && f.Split != "" {
		vals = strings.Split(vals[0], f.Split)
	}

	if len(vals) == 1 && vals[0] == "" {
		rv.Set(reflect.MakeSlice(rv.Type(), 0, 0))
		return nil
	}

	slice := reflect.MakeSlice(rv.Type(), len(vals), len(vals))
	for i, part := range vals {
		if err := setValues(slice.Index(i), []string{part}, f); err != nil {
			return fmt.Errorf(
				"failed to parse slice element at index %d: %w", i, err,
			)
		}
	}

	rv.Set(slice)
	return nil
}

// asTextUnmarshaler checks if the given [reflect.Value] implements the
// [encoding.TextUnmarshaler] interface.
func asTextUnmarshaler(rv reflect.Value) (encoding.TextUnmarshaler, bool) {
	if rv.Type().Implements(typeTextUnmarshaler) {
		if rv.Kind() == reflect.Pointer && rv.IsNil() {
			pointer.Alloc(rv)
		}
		return rv.Interface().(encoding.TextUnmarshaler), true
	}
	if rv.CanAddr() && rv.Addr().Type().Implements(typeTextUnmarshaler) {
		return rv.Addr().Interface().(encoding.TextUnmarshaler), true
	}
	return nil, false
}
