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
//   - Filters out and returns positional (non-flag) arguments.
//
// # Usage
//
// The core of the package is the Set, which manages a collection of flags.
// A default Set is provided for convenience, accessible through top-level
// functions like Add and Parse.
//
// To use the package, define variables, register them as flags using Add,
// and then call Parse to process os.Args.
//
//	func main() {
//		var (
//			port int    = 8080
//			host string = "localhost"
//			verb bool
//		)
//
//		flag.Summary("A simple example of a command-line server application.")
//
//		// Add flags, binding them to local variables.
//		flag.Add(&port, 'p', "port", "Port to listen on")
//		flag.Add(&host, 'h', "host", "Host address to bind to")
//		flag.Add(&verb, 'v', "verbose", "Enable verbose logging")
//
//		// Parse command-line arguments and get positional args.
//		args := flag.Parse()
//
//		fmt.Printf("Starting server on %s:%d (verbose: %v)\n", host, port, verb)
//		fmt.Printf("Positional arguments: %v\n", args)
//	}
//
// The automatically generated help message for the example above is:
//
//	Usage: main [OPTION]...
//
//	A simple example of a command-line server application.
//
//	Options:
//	  -p, --port      Port to listen on (default: 8080)
//	  -h, --host      Host address to bind to (default: localhost)
//	  -v, --verbose   Enable verbose logging
//	      --help      Display this help message and exit
package flag

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"text/tabwriter"
)

// flag holds the metadata for a single registered flag.
type flag struct {
	val  reflect.Value
	def  any // The default value.
	char rune
	name string
	desc string
}

// Set manages a collection of defined flags for a command.
type Set struct {
	cmd   string
	sum   string
	flags []*flag
	char  map[rune]*flag
	name  map[string]*flag
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

	switch e.Kind() {
	case reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64,
		reflect.Bool:
	default:
		panic(fmt.Sprintf("unsupported flag type: %s", e.Kind()))
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

// ErrHelp is a sentinel error returned by Parse when a help flag is encountered.
// This signals to the caller that a help message should be displayed.
var ErrHelp = errors.New("flag: show help")

// Parse processes command-line arguments, mapping them to their corresponding
// flags. It returns a slice of positional arguments (non-flag arguments).
//
// Parsing stops at the first error, when a --help flag is found, or after a
// "--" terminator. If args is nil or empty, os.Args[1:] is used.
func (s *Set) Parse(args []string) ([]string, error) {
	var pos []string
	for i := 0; i < len(args); {
		arg := args[i]
		if len(arg) < 2 || arg[0] != '-' { // Positional argument
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
				return pos, nil
			}
			if arg == "--help" {
				return nil, ErrHelp
			}
			k, err = s.parseName(args, i)
		} else {
			k, err = s.parseChar(args, i)
		}
		if err != nil {
			return nil, err
		}
		i += k
	}
	return pos, nil
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
			// Toggle boolean flags without an explicit value.
			def, ok := f.def.(bool)
			f.val.SetBool(ok && !def)
			continue
		}

		// The value can be the rest of the string or the next argument.
		val := grp[j+1:]
		if val != "" {
			// Value is attached (e.g., -p8080)
			if err := s.setValue(f, val); err != nil {
				return 0, fmt.Errorf("invalid value for flag -%c: %w", char, err)
			}
			return 1, nil
		}

		i++
		if i >= len(args) {
			return 0, fmt.Errorf("flag -%c requires a value", char)
		}
		if err := s.setValue(f, args[i]); err != nil {
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
		b := !f.def.(bool) // Toggle the default value
		if found {
			var err error
			b, err = strconv.ParseBool(val)
			if err != nil {
				return 0, fmt.Errorf("expected boolean for flag --%s, got %q", key, val)
			}
		}
		f.val.SetBool(b)
		return 1, nil
	}

	if !found {
		i++
		if i >= len(args) {
			return 0, fmt.Errorf("flag --%s requires a value", key)
		}
		val = args[i]
	}

	if err := s.setValue(f, val); err != nil {
		return 0, fmt.Errorf("invalid value for flag --%s: %w", key, err)
	}

	if found {
		return 1, nil
	}
	return 2, nil
}

// setValue parses the string value and sets it on the destination variable.
func (s *Set) setValue(def *flag, value string) error {
	val := def.val
	switch kind := val.Kind(); kind {
	case reflect.String:
		val.SetString(value)
	case reflect.Int,
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
	case reflect.Uint,
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
		// Panicking here is reasonable, as Add should prevent unsupported types.
		// This indicates a programming error within the package itself.
		panic(fmt.Sprintf("unsupported flag type: %s", kind))
	}
	return nil
}

// Usage generates a formatted help message, detailing all registered flags,
// their types, descriptions, and default values.
func (s *Set) Usage() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Usage: %s [OPTION]...\n\n", s.cmd)
	if s.sum != "" {
		fmt.Fprintf(&b, "%s\n\n", s.sum)
	}
	fmt.Fprintf(&b, "Options:\n")

	w := tabwriter.NewWriter(&b, 0, 0, 3, ' ', 0)
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
func Add(v any, char rune, name, desc string) { std.Add(v, char, name, desc) }

// Parse processes command-line arguments from os.Args using the default Set.
// It returns the positional arguments.
//
// On a parsing error or if the --help flag is used, this function prints a
// message to the console and exits the program.
func Parse() []string {
	pos, err := std.Parse(os.Args[1:])
	if err == nil {
		return pos
	}
	code := 0
	if !errors.Is(err, ErrHelp) {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		code = 1
	}
	Usage()
	os.Exit(code)
	return nil
}

// Usage prints the help message for the default Set to standard output.
// See Set.Usage for more details.
func Usage() { fmt.Fprint(os.Stdout, std.Usage()) }
