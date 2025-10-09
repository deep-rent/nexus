// Package flag provides a simple, reflection-based command-line flag parsing
// utility. It is designed to be a modern alternative to the standard library's
// flag package, offering a more streamlined API for defining flags.
//
// The package is compliant with common command-line syntax conventions,
// supporting both single-dash shorthand options (POSIX-style, e.g., -v) and
// double-dash long-form options (GNU-style, e.g., --verbose). It also handles
// grouped short options (e.g., -abc) and values attached to short options
// (e.g., -p8080) for POSIX compliance.
//
// Values can be specified using either space or equals sign separators for
// long-form options (e.g., --port 8080 or --port=8080). Boolean flags can be
// toggled from their default value by simply specifying the flag (e.g., -v or
// --verbose) without an explicit value.
//
// # Usage
//
// The core of the package is the Set, which manages a collection of defined
// flags. A default Set is provided for convenience, accessible through
// top-level functions like Add and Parse. To use the package, define variables,
// register them using Add, and then call Parse to process the command-line
// arguments:
//
//	func main() {
//	  var (
//	    port int    = 8080          // Default value
//	    host string = "localhost"   // Default value
//	    verb bool                   // Default is false
//	  )
//
//	  flag.Summary("A one-line summary of what the command does.")
//
//	  // Add flags, binding them to local variables.
//	  flag.Add(&port, "p", "port", "Port to listen on")
//	  flag.Add(&host, "h", "host", "Host address to bind to")
//	  flag.Add(&verb, "v", "verbose", "Enable verbose logging")
//
//	  // Parse the command-line arguments.
//	  flag.Parse()
//
//	  fmt.Printf("Starting server on %s:%d (verbose: %v)\n", host, port, verb)
//	}
//
// The automatically generated help message for the example above would be:
//
//	Usage: foobar [OPTION]...
//
//	A one-line summary of what the command does.
//
//	Options:
//	  -p, --port [int]     Port to listen on (default: 8080)
//	  -h, --host [string]  Host address to bind to (default: localhost)
//	  -v, --verbose        Enable verbose logging
//	      --help           Display this help message and exit
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

// Set manages a collection of defined flags.
type Set struct {
	cmd   string
	sum   string
	flags []*flag
	char  map[rune]*flag
	name  map[string]*flag
}

// New creates a new, empty flag set. The command is used in the usage message.
func New(cmd string) *Set {
	return &Set{
		cmd:  cmd,
		char: make(map[rune]*flag),
		name: make(map[string]*flag),
	}
}

// Summary sets a one-line description for the command, shown in the
// usage message. If not set, no summary is displayed.
func (s *Set) Summary(sum string) { s.sum = sum }

// Add registers a new flag with the set. It binds a command-line option to the
// variable pointed to by v. The variable's initial value is used as the
// default, if present. The variable must be a pointer to one of the supported
// types: string, int, uint, float, or bool and their sized variants.
//
// Th char parameter is the single-letter abbreviation for the flag (e.g., 'v'
// for -v). It can be zero if no short name is desired. The name parameter is
// the long-form name (e.g., "verbose" for --verbose). It can be empty if no
// long name is desired. At least one of char or name must be provided. Both
// names are matched case-sensitively. Duplicate names will cause a panic.
// Additionally, a description should be specified to explain the flag's purpose
// in the help message.
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

// ErrHelp acts as a signal to display a help message and exit successfully
// rather than indicating a failure.
var ErrHelp = errors.New("flag: show help")

// Parse maps command-line arguments to flags and returns only the positional
// arguments (those that are not flags).
//
// It must be called after all flags have been added. If a --help flag is
// encountered, it returns ErrHelp. Other errors indicate parsing issues.
// The args parameter allows feeding in a custom argument slice; if a nil or
// empty slice is given, the system's input arguments (os.Args) are parsed.
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
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		b := val.Type().Bits()
		i, err := strconv.ParseInt(value, 10, b)
		if err != nil {
			return err
		}
		val.SetInt(i)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
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
		keys := s.format(f)
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

// format builds the left-hand side of a help message line.
// Example: "-v, --verbose <bool>"
func (s *Set) format(f *flag) string {
	var out string
	if f.char != 0 {
		out = "-" + string(f.char) + ", "
	} else {
		out = "    "
	}
	if f.name != "" {
		out += "--" + f.name
	}
	if f.name != "help" && f.val.Kind() != reflect.Bool {
		out += fmt.Sprintf(" [%s]", f.val.Kind())
	}
	return out
}

// std is the default, package-level flag Set.
var std = New(filepath.Base(os.Args[0]))

// Summary sets a one-line description for the command, shown in the
// usage message of the default set. If not set, no summary is displayed.
func Summary(sum string) { std.Summary(sum) }

// Add registers a flag with the default set.
//
// See Set.Add for details.
func Add(v any, char rune, name, desc string) { std.Add(v, char, name, desc) }

// Parse parses command-line arguments from os.Args and returns the positional
// arguments (those that are not flags).
//
// This function must be called after all flags have been added. If a --help
// flag is encountered, it prints the usage message and exits. On error, it
// prints the error message and exits with a non-zero status code.
//
// See Set.Parse for details.
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

// Usage prints the help message for the default set.
//
// See Set.Usage for details.
func Usage() { fmt.Fprint(os.Stdout, std.Usage()) }
