// Package flag provides a simple, reflection-based command-line flag parsing
// utility. It is designed to be a modern alternative to the standard library's
// flag package, offering a more streamlined API for defining flags.
//
// The core of the package is the Set, which manages a collection of defined
// flags. A default Set is provided for convenience, accessible through
// top-level functions like Add and Parse.
//
// Usage:
//
//	func main() {
//	  var (
//	    port    int
//	    host    string
//	    verbose bool
//	    timeout time.Duration
//	  )
//
//	  // Add flags, binding them to local variables.
//	  flag.Add(&port, "p", "port", "Port to listen on")
//	  flag.Add(&host, "", "host", "Host address to bind to")
//	  flag.Add(&verbose, "v", "verbose", "Enable verbose logging")
//	  flag.Add(&timeout, "t", "timeout", "Server shutdown timeout")
//
//	  // Parse the command-line arguments.
//	  flag.Parse()
//
//	  fmt.Printf("Starting server on %s:%d (verbose: %v, timeout: %s)\n",
//	    host, port, verbose, timeout)
//	}
//
// The automatically generated help message for the example above would be:
//
//	Usage of my-app:
//	  -p, --port <int>           Port to listen on
//	      --host <string>        Host address to bind to
//	  -v, --verbose <bool>       Enable verbose logging
//	  -t, --timeout <duration>   Server shutdown timeout
//	  -h, --help                 Display this help message and exit
package flag

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

// definition holds the metadata for a single registered flag.
type definition struct {
	val   reflect.Value // Pointer to the variable where the value is stored.
	short string        // POSIX-style short name (e.g., "v")
	long  string        // GNU-style long name (e.g., "verbose")
	desc  string
}

// Set manages a collection of defined flags.
type Set struct {
	title string
	flags []*definition
}

// New creates a new, empty flag set. The title is used in the usage message.
func New(title string) *Set {
	return &Set{title: title}
}

// Add registers a new flag with the set. It binds a command-line flag to the
// variable pointed to by v. The variable must be a pointer to one of the
// supported types: string, int, uint, float, or bool and their sized variants.
// The flag must have at least a short or long name. Short names are single
// characters (e.g., "v"), while long names are more descriptive (e.g.,
// "verbose"). Names are matched case-sensitively. The description provides a
// brief explanation of the flag's purpose for use in the help message.
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
	m := &definition{
		val:   val.Elem(),
		short: short,
		long:  long,
		desc:  desc,
	}
	s.flags = append(s.flags, m)
}

// Parse maps command-line arguments to flags. It must be called
// after all flags have been added. If a help flag (-h or --help) is
// encountered, it prints the usage message and exits. The args parameter
// allows specifying a custom argument slice; if nil or empty, the system's
// arguments (os.Args) are used.
func (s *Set) Parse(args ...string) {
	if len(args) == 0 {
		args = os.Args[1:]
	}
	s.parse(args)
}

// parse is the main loop that processes the argument slice.
func (s *Set) parse(args []string) {
	for i := 0; i < len(args); {
		arg := args[i]
		if len(arg) < 2 || arg[0] != '-' {
			i++ // Not a flag, advance.
			continue
		}
		if arg == "--" {
			return // End of flags.
		}

		if strings.HasPrefix(arg, "--") {
			i += s.readLong(args, i)
		} else {
			i += s.readShort(args, i)
		}
	}
}

// findShort queries a flag definition by its short name.
func (s *Set) findShort(name string) *definition {
	for _, f := range s.flags {
		if f.short == name {
			return f
		}
	}
	return nil
}

// findLong queries a flag definition by its long name.
func (s *Set) findLong(name string) *definition {
	for _, f := range s.flags {
		if f.long == name {
			return f
		}
	}
	return nil
}

// readShort handles short-form flags (e.g., -v, -abc, -p8080).
// It returns the number of arguments consumed (1 or 2).
func (s *Set) readShort(args []string, i int) int {
	arg := args[i]
	names := strings.TrimPrefix(arg, "-")

	for j, char := range names {
		name := string(char)
		if name == "h" {
			s.Usage()
			os.Exit(0)
		}

		def := s.findShort(name)
		if def == nil {
			s.errorf("Unknown flag '-%s' in group '%s'", name, arg)
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
				s.errorf("Invalid value for flag '-%s': %v", name, err)
			}
			return 1 // Consumed one argument, done with this group.
		}

		// Value is the next argument (e.g., -p 8080)
		i++
		if i >= len(args) {
			s.errorf("Flag '-%s' requires a value", name)
		}
		if err := s.setValue(def, args[i]); err != nil {
			s.errorf("Invalid value for flag '-%s': %v", name, err)
		}
		return 2 // Consumed two arguments.
	}

	return 1 // Consumed one argument (for boolean groups).
}

// readLong handles a long-form flag (e.g., --verbose, --port=8080).
// It returns the number of arguments consumed (1 or 2).
func (s *Set) readLong(args []string, i int) int {
	arg := args[i]
	name, value, hasValue := strings.Cut(strings.TrimPrefix(arg, "--"), "=")

	def := s.findLong(name)
	if def == nil {
		s.errorf("Unknown flag '%s'", arg)
	}

	if def.val.Kind() == reflect.Bool {
		val := true
		if hasValue {
			var err error
			val, err = strconv.ParseBool(value)
			if err != nil {
				s.errorf("Expected true or false for flag '%s', got '%s'", arg, value)
			}
		}
		def.val.SetBool(val)
		return 1
	}

	if !hasValue {
		i++
		if i >= len(args) {
			s.errorf("Flag '%s' requires a value", arg)
		}
		value = args[i]
	}

	if err := s.setValue(def, value); err != nil {
		s.errorf("Invalid value for flag '%s': %v", arg, err)
	}

	if hasValue {
		return 1
	}
	return 2
}

// setValue parses the string value and sets it on the destination variable.
func (s *Set) setValue(def *definition, value string) error {
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
	all := append(s.flags, &definition{
		short: "h",
		long:  "help",
		desc:  "Display this help message and exit",
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
func (s *Set) format(f *definition) string {
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

// errorf prints an error message and the usage help, then exits.
func (s *Set) errorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	s.Usage()
	os.Exit(1)
}

var std = New(filepath.Base(os.Args[0]))

// Add registers a flag with the default set.
func Add(v any, short, long, desc string) { std.Add(v, short, long, desc) }

// Parse parses command-line arguments using the default set.
func Parse() { std.Parse() }

// Usage prints the help message for the default set.
func Usage() { std.Usage() }
