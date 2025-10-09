// Package flag provides a simple, reflection-based parser for command-line
// arguments. It offers a streamlined API and support for POSIX/GNU conventions.
//
// # Features
//
//   - Supports POSIX-style short options (-v) and GNU-style long options
//     (--verbose).
//   - Parses grouped short options (-abc) and values attached to short options
//     (-p8080).
//   - Handles space or equals sign separators for long option values
//     (--port 8080, --port=8080).
//   - Toggles boolean flags from their default value when present
//     (--no-format, --disable).
//   - Generates an automatic help message for the --help flag.
//   - Parses named positional arguments (required, optional, and variadic).
//
// # Usage
//
// The core of the package is the Set, which manages a collection of flags and
// arguments. A default Set is provided for convenience, accessible through
// top-level functions like Add, Arg, and Parse.
//
// To use the package, define variables, register them as flags or arguments,
// and then call Parse to process os.Args.
//
//	func main() {
//	  var (
//	    verbose bool
//	    depth   int = 1
//	    source  string
//	    target  string
//	  )
//
//	  flag.Summary("Creates copies of files and directories.")
//
//	  // Add flags, binding them to local variables.
//	  flag.Add(&verbose, 'v', "verbose", "Enable verbose logging")
//	  flag.Add(&depth, 'd', "depth", "Maximum recursion depth (default: 1)")
//
//	  // Add named positional arguments.
//	  flag.Arg(&src, "source", "The source file or directory", true)
//	  flag.Arg(&dst, "target", "The target file or directory", true)
//
//	  // Parse command-line arguments.
//	  flag.Parse()
//
//	  if verbose {
//	    fmt.Printf("Copy from %s to %s (depth: %d)\n", source, target, depth)
//	  }
//	}
//
// The automatically generated help message for the example above is:
//
//	Usage: copy [OPTION]... <SOURCE> <TARGET>
//
//	Creates copies of files and directories.
//
//	Arguments:
//	  SOURCE     The source file or directory
//	  TARGET     The target file or directory
//
//	Options:
//	  -d, --depth     Maximum recursion depth (default: 1)
//	  -v, --verbose   Enable verbose logging
//	      --help      Display this help message and exit
package flag

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"text/tabwriter"
)

// flag holds metadata for a single registered flag.
type flag struct {
	val  reflect.Value
	def  any
	char rune
	name string
	desc string
}

// toggle safely toggles a boolean flag's value from its default.
func (f *flag) toggle() {
	def, _ := f.def.(bool)
	f.val.SetBool(!def)
}

// arg holds metadata for a named positional argument.
type arg struct {
	val      reflect.Value
	name     string
	desc     string
	required bool
	variadic bool
}

// Set manages a collection of defined flags for a command.
type Set struct {
	cmd   string
	sum   string
	flags []*flag
	char  map[rune]*flag
	name  map[string]*flag
	args  []*arg
}

// New creates a new, empty flag Set. The cmd name is used in the generated
// usage message.
func New(cmd string) *Set {
	return &Set{
		cmd:  cmd,
		char: make(map[rune]*flag),
		name: make(map[string]*flag),
	}
}

// Summary sets a one-line synopsis for the command, which is displayed
// in the usage message. If not set, no summary is shown.
func (s *Set) Summary(sum string) { s.sum = sum }

// Add registers a new flag with the set. It binds a command-line option to the
// variable pointed to by v. The variable's initial value is captured as the
// default. The destination v must be a pointer to a bool, float, int, string,
// or uint, including their sized variants (e.g., int64).
//
// The char parameter is the single-letter shorthand name (e.g., 'v' for -v). It
// can be zero if no short name is desired. The name parameter is the long-form
// name (e.g., "verbose" for --verbose) and can be empty if no long name is
// desired. At least one name must be provided. Duplicate names cause the
// method to panic.
func (s *Set) Add(v any, char rune, name, desc string) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer {
		panic("flag destination must be a pointer")
	}
	if char == 0 && len(name) == 0 {
		panic("flag must be named")
	}
	if len(name) == 1 {
		panic("name must have at least two characters")
	}
	if char != 0 {
		if _, exists := s.char[char]; exists {
			panic(fmt.Sprintf("duplicate flag -%c", char))
		}
	}
	if name != "" {
		if _, exists := s.name[name]; exists {
			panic(fmt.Sprintf("duplicate flag --%s", name))
		}
	}

	e := rv.Elem()
	if kind := e.Kind(); !isPrimitive(kind) {
		panic(fmt.Sprintf("unsupported flag type: %s", kind))
	}

	f := &flag{
		val:  e,
		def:  e.Interface(), // Capture initial value as default.
		char: char,
		name: name,
		desc: desc,
	}
	s.flags = append(s.flags, f)
	if char != 0 {
		s.char[char] = f
	}
	if name != "" {
		s.name[name] = f
	}
}

// Arg registers a named positional argument. The destination v must be a
// pointer to a supported scalar type or a pointer to a slice for a variadic
// argument. The name is conventionally uppercase (e.g., "SOURCE"). A
// description is required for the help message.
//
// Arguments are parsed in the order they are defined. Required arguments must
// precede optional ones. A variadic argument must be the last one defined and
// will consume all remaining command-line arguments.
func (s *Set) Arg(v any, name, desc string, required bool) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer {
		panic("argument destination must be a pointer")
	}

	e := rv.Elem()
	variadic := e.Kind() == reflect.Slice

	if len(s.args) > 0 {
		last := s.args[len(s.args)-1]
		if last.variadic {
			panic("cannot add argument after a variadic argument")
		}
		if !last.required && required {
			panic("required arguments must be defined before optional ones")
		}
	}

	if kind := e.Kind(); !variadic && !isPrimitive(kind) {
		panic(fmt.Sprintf("unsupported argument type: %s", kind))
	}

	a := &arg{
		val:      e,
		name:     strings.ToUpper(name),
		desc:     desc,
		required: required,
		variadic: variadic,
	}
	s.args = append(s.args, a)
}

// isPrimitive reports whether k is a supported primitive kind for flags/args.
func isPrimitive(k reflect.Kind) bool {
	switch k {
	case
		reflect.String,
		reflect.Bool,
		reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64,
		reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64,
		reflect.Float32,
		reflect.Float64:
		return true
	}
	return false
}

// ErrHelp is a sentinel error returned by Parse when it encounters a help flag.
// This signals to the caller that a help message should be displayed.
var ErrHelp = errors.New("flag: show help")

// Parse processes command-line arguments, mapping them to their corresponding
// flags and named arguments. It returns an error if parsing fails.
//
// If named arguments are defined, Parse will attempt to satisfy them from the
// positional arguments. If there are missing, extra, or invalid arguments, it
// returns an error.
//
// Parsing stops at the first error, when a --help flag is found, or after a
// "--" terminator. If args is nil or empty, os.Args[1:] is used.
func (s *Set) Parse(args []string) error {
	var pos []string
	for i := 0; i < len(args); {
		arg := args[i]
		if len(arg) > 0 && arg[0] != '-' { // Positional argument
			pos = append(pos, arg)
			i++
			continue
		}
		if len(arg) < 2 { // Handle "-" as a positional argument
			pos = append(pos, arg)
			i++
			continue
		}

		var (
			k   int
			err error
		)
		if strings.HasPrefix(arg, "--") {
			if len(arg) == 2 { // End of flags marker "--"
				pos = append(pos, args[i+1:]...)
				break // Stop flag parsing
			}
			if arg == "--help" {
				return ErrHelp
			}
			k, err = s.parseName(args, i)
		} else {
			k, err = s.parseChar(args, i)
		}
		if err != nil {
			return err
		}
		i += k
	}
	// If named arguments are defined, consume the positional args.
	if len(s.args) > 0 {
		return s.parseArgs(pos)
	}
	// If no named arguments are defined, any positional args are an error.
	if len(pos) > 0 {
		return fmt.Errorf("unexpected positional arguments: %v", pos)
	}
	return nil
}

// parseArgs consumes the positional arguments based on configured rules.
func (s *Set) parseArgs(pos []string) error {
	for _, a := range s.args {
		if a.variadic {
			if err := s.setSlice(a.val, pos); err != nil {
				return fmt.Errorf(
					"invalid value for variadic argument %s: %w", a.name, err,
				)
			}
			pos = nil // All arguments consumed.
			break
		}

		if len(pos) == 0 {
			if a.required {
				return fmt.Errorf("missing required argument <%s>", a.name)
			}
			break
		}
		if err := s.setValue(a.val, pos[0]); err != nil {
			return fmt.Errorf("invalid value for argument %s: %w", a.name, err)
		}
		pos = pos[1:]
	}

	if len(pos) > 0 {
		return fmt.Errorf("too many arguments: %v", pos)
	}

	return nil // Success
}

// parseChar handles abbreviated flags (e.g., -v, -abc, -p8080).
// It returns the number of arguments consumed and any error encountered.
func (s *Set) parseChar(args []string, i int) (int, error) {
	arg := args[i]
	grp := strings.TrimPrefix(arg, "-")

	for j, char := range grp {
		f := s.char[char]
		if f == nil {
			return 0, fmt.Errorf("unknown flag -%c", char)
		}

		if f.val.Kind() == reflect.Bool {
			f.toggle()
			continue
		}

		// The value can be the rest of the string or the next argument.
		val := grp[j+1:]
		if val != "" {
			// Value is attached (e.g., -p8080)
			if err := s.setValue(f.val, val); err != nil {
				return 0, fmt.Errorf("invalid value for flag -%c: %w", char, err)
			}
			return 1, nil
		}

		i++
		if i >= len(args) {
			return 0, fmt.Errorf("flag -%c requires a value", char)
		}
		if err := s.setValue(f.val, args[i]); err != nil {
			return 0, fmt.Errorf("invalid value for flag -%c: %w", char, err)
		}
		return 2, nil
	}

	return 1, nil
}

// parseName handles a named flag (e.g., --verbose, --port=8080).
// It returns the number of arguments consumed and any error encountered.
func (s *Set) parseName(args []string, i int) (int, error) {
	arg := args[i]
	key, val, found := strings.Cut(arg[2:], "=")

	f := s.name[key]
	if f == nil {
		return 0, fmt.Errorf("unknown flag --%s", key)
	}

	if f.val.Kind() == reflect.Bool {
		f.toggle()
		if found {
			b, err := strconv.ParseBool(val)
			if err != nil {
				return 0, fmt.Errorf("expected boolean for flag --%s, got %q", key, val)
			}
			f.val.SetBool(b) // Allow explicit override
		}
		return 1, nil
	}

	if !found {
		i++
		if i >= len(args) {
			return 0, fmt.Errorf("flag --%s requires a value", key)
		}
		val = args[i]
	}

	if err := s.setValue(f.val, val); err != nil {
		return 0, fmt.Errorf("invalid value for flag --%s: %w", key, err)
	}

	if found {
		return 1, nil
	}
	return 2, nil
}

// setValue parses the string value and sets it on the destination variable.
func (s *Set) setValue(val reflect.Value, value string) error {
	switch kind := val.Kind(); kind {
	case reflect.String:
		val.SetString(value)
	case reflect.Bool:
		b, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		val.SetBool(b)
	case
		reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64:
		b := val.Type().Bits()
		i, err := strconv.ParseInt(value, 10, b)
		if err != nil {
			return err
		}
		val.SetInt(i)
	case
		reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64:
		b := val.Type().Bits()
		u, err := strconv.ParseUint(value, 10, b)
		if err != nil {
			return err
		}
		val.SetUint(u)
	case reflect.Float32, reflect.Float64:
		b := val.Type().Bits()
		f, err := strconv.ParseFloat(value, b)
		if err != nil {
			return err
		}
		val.SetFloat(f)
	default:
		// Panicking here is reasonable, as Add and Arg should prevent unsupported
		// types. This indicates a programming error within the package itself.
		panic(fmt.Sprintf("unsupported destination type: %s", kind))
	}
	return nil
}

// setSlice populates a slice from a slice of string values.
func (s *Set) setSlice(src reflect.Value, vals []string) error {
	typ := src.Type()
	dst := reflect.MakeSlice(typ, 0, len(vals))
	for _, v := range vals {
		e := reflect.New(typ.Elem()).Elem()
		if err := s.setValue(e, v); err != nil {
			return err
		}
		dst = reflect.Append(dst, e)
	}
	src.Set(dst)
	return nil
}

// Usage generates a formatted help message, detailing all registered flags,
// their types, descriptions, and default values.
func (s *Set) Usage() string {
	var b strings.Builder

	// Build the main usage line, including named arguments.
	var args []string
	for _, a := range s.args {
		if a.variadic {
			args = append(args, fmt.Sprintf("[%s]...", a.name))
		} else if a.required {
			args = append(args, fmt.Sprintf("<%s>", a.name))
		} else {
			args = append(args, fmt.Sprintf("[%s]", a.name))
		}
	}

	fmt.Fprintf(
		&b,
		"Usage: %s [OPTION]... %s\n\n",
		s.cmd,
		strings.Join(args, " "),
	)

	if s.sum != "" {
		fmt.Fprintf(&b, "%s\n\n", s.sum)
	}

	w := tabwriter.NewWriter(&b, 0, 0, 3, ' ', 0)

	if len(s.args) > 0 {
		fmt.Fprint(&b, "Arguments:\n")
		for _, a := range s.args {
			fmt.Fprintf(w, "  %s\t%s\n", a.name, a.desc)
		}
		w.Flush() // Align both, the argument and the option columns
		fmt.Fprint(&b, "\n")
	}

	fmt.Fprintf(&b, "Options:\n")
	all := append(s.flags, &flag{
		name: "help",
		desc: "Display this help message and exit",
	})

	for _, f := range all {
		// Build the left-hand side of the line
		// Example: "-p, --port"
		var keys string
		if f.char != 0 {
			keys = "-" + string(f.char)
		} else {
			keys = "  "
		}
		if f.name != "" {
			if f.char != 0 {
				keys += ","
			} else {
				keys += " "
			}
			keys += " --" + f.name
		}

		// Include the value type for non-bool flags.
		// if f.name != "help" && f.val.Kind() != reflect.Bool {
		//     keys += fmt.Sprintf(" [%s]", f.val.Kind())
		// }

		desc := f.desc
		// Only show default value if it's not the zero value for its type.
		if f.def != nil && !reflect.ValueOf(f.def).IsZero() {
			desc += fmt.Sprintf(" (default: %v)", f.def)
		}
		// Write tab-separated columns; tabwriter handles the spacing.
		fmt.Fprintf(w, "  %s\t%s\n", keys, desc)
	}

	w.Flush() // Finalize formatting.
	return b.String()
}

// std is the default, package-level flag Set.
var std = New(filepath.Base(os.Args[0]))

// Summary sets a one-line description for the command on the default Set.
// See Set.Summary for more details.
func Summary(sum string) { std.Summary(sum) }

// Add registers a flag with the default Set.
// See Set.Add for more details.
func Add(v any, char rune, name, desc string) {
	std.Add(v, char, name, desc)
}

// Arg registers a named positional argument with the default Set.
// See Set.Arg for more details.
func Arg(v any, name, desc string, required bool) {
	std.Arg(v, name, desc, required)
}

// Parse processes command-line arguments from os.Args using the default Set.
// It returns the unconsumed positional arguments (which is typically an empty
// slice if named arguments are defined and parsing is successful).
//
// On a parsing error or if the --help flag is used, this function prints a
// message to the console and exits the program.
func Parse() {
	err := std.Parse(os.Args[1:])
	if err == nil {
		return
	}
	code := 1
	var w io.Writer
	if errors.Is(err, ErrHelp) {
		code = 0
		w = os.Stdout
	} else {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		w = os.Stderr
	}
	fmt.Fprint(w, std.Usage())
	os.Exit(code)
}

// Usage prints the help message for the default Set to standard output.
// See Set.Usage for more details.
func Usage() { fmt.Fprint(os.Stdout, std.Usage()) }
