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
// The core of the package is the Set, which manages a collection of defined
// flags. A default Set is provided for convenience, accessible through
// top-level functions like Add and Parse.
//
// Usage:
//
//	func main() {
//	  var (
//	    port int
//	    host string
//	    verb bool
//	  )
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
//	Usage of my-app:
//	  -p, --port <int>       Port to listen on
//	  -h, --host <string>    Host address to bind to
//	  -v, --verbose <bool>   Enable verbose logging
//	      --help             Display this help message and exit
package flag

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

// flag holds the metadata for a single registered flag.
type flag struct {
	val   reflect.Value
	short string
	long  string
	desc  string
}

// Set manages a collection of defined flags.
type Set struct {
	title string
	flags []*flag
}

// New creates a new, empty flag set. The title is used in the usage message.
func New(title string) *Set {
	return &Set{title: title}
}

// Add registers a new flag with the set. It binds a command-line option to the
// variable pointed to by v. The variable must be a pointer to one of the
// supported types: string, int, uint, float, or bool and their sized variants.
//
// The flag must have at least a non-empty short or long name. Short names are
// single-letter abbreviations (e.g., "v"), while long-form names are more
// descriptive (e.g., "verbose"). Names are matched case-sensitively. The
// description provides a brief explanation of the flag's purpose for use in
// the help message.
func (s *Set) Add(v any, short, long, desc string) {
	val := reflect.ValueOf(v)
	if val.Kind() != reflect.Pointer {
		panic("flag destination must be a pointer")
	}
	if short == "" && long == "" {
		panic("flag must have at least a short or long name")
	}
	if len(short) > 1 {
		panic("short name must be a single character")
	}
	m := &flag{
		val:   val.Elem(),
		short: short,
		long:  long,
		desc:  desc,
	}
	s.flags = append(s.flags, m)
}

// errShowHelp is a sentinel error that acts as a signal to display a help
// message and exit successfully rather than indicating a failure.
var errShowHelp = errors.New("show help")

// Parse maps command-line arguments to flags. It must be called
// after all flags have been added. If a --help flag is encountered, it prints
// the usage message and exits. The args parameter allows passing a custom
// argument slice; if nil or empty, the system's arguments (os.Args) are used.
func (s *Set) Parse(args ...string) {
	if len(args) == 0 {
		args = os.Args[1:]
	}
	if err := s.parse(args); err != nil {
		code := 0
		if !errors.Is(err, errShowHelp) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			code = 1
		}
		s.Usage()
		os.Exit(code)
	}
}

// parse is the main loop that processes the argument slice.
func (s *Set) parse(args []string) error {
	for i := 0; i < len(args); {
		arg := args[i]
		if len(arg) < 2 || arg[0] != '-' {
			i++ // Not a flag, advance.
			continue
		}
		if arg == "--" {
			return nil // End of flags.
		}
		if arg == "--help" {
			return errShowHelp
		}
		var (
			skip int
			err  error
		)
		if strings.HasPrefix(arg, "--") {
			skip, err = s.readLong(args, i)
		} else {
			skip, err = s.read(args, i)
		}
		if err != nil {
			return err
		}
		i += skip
	}
	return nil
}

// find queries a flag definition by its short name.
func (s *Set) find(name string) *flag {
	for _, f := range s.flags {
		if f.short == name {
			return f
		}
	}
	return nil
}

// findLong queries a flag definition by its long name.
func (s *Set) findLong(name string) *flag {
	for _, f := range s.flags {
		if f.long == name {
			return f
		}
	}
	return nil
}

// read handles short-form flags (e.g., -v, -abc, -p8080).
// It returns the number of arguments consumed and any error encountered.
func (s *Set) read(args []string, i int) (int, error) {
	arg := args[i]
	names := strings.TrimPrefix(arg, "-")

	for j, char := range names {
		name := string(char)
		def := s.find(name)
		if def == nil {
			return 0, fmt.Errorf("unknown flag %q in group %q", name, arg)
		}

		if def.val.Kind() == reflect.Bool {
			def.val.SetBool(true)
			continue // Continue to next character in the group.
		}

		// If not a boolean, it requires a value.
		// The value can be the rest of the string or the next argument.
		value := names[j+1:]
		if value != "" {
			// Value is attached (e.g., -p8080)
			if err := s.setValue(def, value); err != nil {
				return 0, fmt.Errorf("invalid value for flag %q: %w", name, err)
			}
			return 1, nil // Consumed one argument, done with this group.
		}

		// Value is the next argument (e.g., -p 8080)
		i++
		if i >= len(args) {
			return 0, fmt.Errorf("flag %q requires a value", name)
		}
		if err := s.setValue(def, args[i]); err != nil {
			return 0, fmt.Errorf("invalid value for flag %q: %w", name, err)
		}
		return 2, nil // Consumed two arguments.
	}

	return 1, nil // Consumed one argument (for boolean groups).
}

// readLong handles a long-form flag (e.g., --verbose, --port=8080).
// It returns the number of arguments consumed and any error encountered.
func (s *Set) readLong(args []string, i int) (int, error) {
	arg := args[i]
	name, value, hasValue := strings.Cut(strings.TrimPrefix(arg, "--"), "=")

	def := s.findLong(name)
	if def == nil {
		return 0, fmt.Errorf("unknown flag %q", arg)
	}

	if def.val.Kind() == reflect.Bool {
		val := true
		if hasValue {
			var err error
			val, err = strconv.ParseBool(value)
			if err != nil {
				return 0, fmt.Errorf("expected boolean for flag %q, got %q", arg, value)
			}
		}
		def.val.SetBool(val)
		return 1, nil
	}

	if !hasValue {
		i++
		if i >= len(args) {
			return 0, fmt.Errorf("flag %q requires a value", arg)
		}
		value = args[i]
	}

	if err := s.setValue(def, value); err != nil {
		return 0, fmt.Errorf("invalid value for flag %q: %w", arg, err)
	}

	if hasValue {
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
		return fmt.Errorf("unsupported flag type: %s", kind)
	}
	return nil
}

// Usage prints a formatted help message to os.Stdout.
func (s *Set) Usage() {
	var b strings.Builder
	fmt.Fprintf(&b, "Usage of %s:\n", s.title)
	all := append(s.flags, &flag{
		long: "help",
		desc: "Display this help message and exit",
	})
	offset := 0
	for _, f := range all {
		l := len(s.format(f))
		if l > offset {
			offset = l
		}
	}
	for _, f := range all {
		names := s.format(f)
		space := strings.Repeat(" ", offset-len(names)+2)
		fmt.Fprintf(&b, "  %s%s%s\n", names, space, f.desc)
	}
	fmt.Fprint(os.Stdout, b.String())
}

// format creates the string representation of flag names.
// Example: "-v, --verbose <bool>"
func (s *Set) format(f *flag) string {
	var parts []string
	if f.short != "" {
		parts = append(parts, "-"+f.short)
	}
	if f.long != "" {
		parts = append(parts, "--"+f.long)
	}
	names := strings.Join(parts, ", ")
	if f.long == "help" {
		return names
	}
	// Pad short-only flags for alignment.
	if f.long == "" {
		names = "  " + names
	}
	typeStr := fmt.Sprintf("<%s>", f.val.Kind().String())
	return fmt.Sprintf("%-20s %s", names, typeStr)
}

var std = New(filepath.Base(os.Args[0]))

// Add registers a flag with the default set.
func Add(v any, short, long, desc string) { std.Add(v, short, long, desc) }

// Parse parses command-line arguments using the default set.
func Parse(args ...string) { std.Parse(args...) }

// Usage prints the help message for the default set.
func Usage() { std.Usage() }
