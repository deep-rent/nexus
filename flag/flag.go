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
//	    verb bool                  // Default is false
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
//	       foobar --help
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
)

// flag holds the metadata for a single registered flag.
type flag struct {
	val   reflect.Value
	def   any // The default value.
	short string
	long  string
	desc  string
}

// Set manages a collection of defined flags.
type Set struct {
	cmd   string
	sum   string
	flags []*flag
}

// New creates a new, empty flag set. The command is used in the usage message.
func New(cmd string) *Set {
	return &Set{cmd: cmd}
}

// Summary sets a one-line description for the command, shown in the
// usage message. If not set, no summary is displayed.
func (s *Set) Summary(sum string) { s.sum = sum }

// Add registers a new flag with the set. It binds a command-line option to the
// variable pointed to by v. The variable's initial value is used as the
// default, if present. The variable must be a pointer to one of the supported
// types: string, int, uint, float, or bool and their sized variants.
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
	elem := val.Elem()
	m := &flag{
		val:   elem,
		def:   elem.Interface(), // Capture initial value as default.
		short: short,
		long:  long,
		desc:  desc,
	}
	s.flags = append(s.flags, m)
}

// ErrShowHelp acts as a signal to display a help message and exit successfully
// rather than indicating a failure.
var ErrShowHelp = errors.New("show help")

// Parse maps command-line arguments to flags.
//
// It must be called after all flags have been added. If a --help flag i
// encountered, it returns ErrShowHelp. Other errors indicate parsing issues.
// The args parameter allows feeding in a custom argument slice; if a nil or
// empty slice is given, the system's input arguments (os.Args) are parsed.
func (s *Set) Parse(args []string) error {
	return s.parse(args)
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
			return ErrShowHelp
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
	keys := strings.TrimPrefix(arg, "-")

	for j, char := range keys {
		key := string(char)
		def := s.find(key)
		if def == nil {
			return 0, fmt.Errorf("unknown flag %q in group %q", key, arg)
		}

		if def.val.Kind() == reflect.Bool {
			def.val.SetBool(true)
			continue // Continue to next character in the group.
		}

		// The value can be the rest of the string or the next argument.
		val := keys[j+1:]
		if val != "" {
			// Value is attached (e.g., -p8080)
			if err := s.setValue(def, val); err != nil {
				return 0, fmt.Errorf("invalid value for flag %q: %w", key, err)
			}
			return 1, nil
		}

		i++
		if i >= len(args) {
			return 0, fmt.Errorf("flag %q requires a value", key)
		}
		if err := s.setValue(def, args[i]); err != nil {
			return 0, fmt.Errorf("invalid value for flag %q: %w", key, err)
		}
		return 2, nil
	}

	return 1, nil
}

// readLong handles a long-form flag (e.g., --verbose, --port=8080).
// It returns the number of arguments consumed and any error encountered.
func (s *Set) readLong(args []string, i int) (int, error) {
	arg := args[i]
	key, val, found := strings.Cut(strings.TrimPrefix(arg, "--"), "=")

	def := s.findLong(key)
	if def == nil {
		return 0, fmt.Errorf("unknown flag %q", arg)
	}

	if def.val.Kind() == reflect.Bool {
		b := true
		if found {
			var err error
			b, err = strconv.ParseBool(val)
			if err != nil {
				return 0, fmt.Errorf("expected boolean for flag %q, got %q", arg, val)
			}
		}
		def.val.SetBool(b)
		return 1, nil
	}

	if !found {
		i++
		if i >= len(args) {
			return 0, fmt.Errorf("flag %q requires a value", arg)
		}
		val = args[i]
	}

	if err := s.setValue(def, val); err != nil {
		return 0, fmt.Errorf("invalid value for flag %q: %w", arg, err)
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
		// return fmt.Errorf("unsupported flag type: %s", kind)
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
	fmt.Fprintf(&b, "Usage: %s [OPTION]...\n", s.cmd)
	fmt.Fprintf(&b, "       %s --help\n\n", s.cmd)
	if s.sum != "" {
		fmt.Fprintf(&b, "%s\n\n", s.sum)
	}
	fmt.Fprintf(&b, "Options:\n")
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
		desc := f.desc
		if def := s.formatDefault(f); def != "" {
			desc += " " + def
		}
		fmt.Fprintf(&b, "  %s%s%s\n", names, space, desc)
	}
	return b.String()
}

// format builds the left-hand side of a help message line.
// Example: "-v, --verbose <bool>"
func (s *Set) format(f *flag) string {
	var out string
	if f.short != "" {
		out = "-" + f.short + ", "
	} else {
		out = "    "
	}
	if f.long != "" {
		out += "--" + f.long
	}
	if f.long != "help" && f.val.Kind() != reflect.Bool {
		out += fmt.Sprintf(" [%s]", f.val.Kind())
	}
	return out
}

// formatDefault creates the default value string, like "(default: 8080)".
// It returns an empty string for zero-value defaults to keep the help concise.
func (s *Set) formatDefault(f *flag) string {
	if f.def == nil {
		return ""
	}
	val := reflect.ValueOf(f.def)
	// Don't show default for zero-values.
	if val.IsZero() {
		return ""
	}
	return fmt.Sprintf("(default: %v)", f.def)
}

// std is the default, package-level flag Set.
var std = New(filepath.Base(os.Args[0]))

// Summary sets a one-line description for the command, shown in the
// usage message of the default set. If not set, no summary is displayed.
func Summary(sum string) { std.Summary(sum) }

// Add registers a flag with the default set.
func Add(v any, short, long, desc string) { std.Add(v, short, long, desc) }

// Parse parses command-line arguments using the default set.
//
// This function must be called after all flags have been added. If a --help
// flag is encountered, it prints the usage message and exits. On error, it
// prints the error message and exits with a non-zero status code.
func Parse() {
	err := std.Parse(os.Args[1:])
	if err == nil {
		return
	}
	code := 0
	if !errors.Is(err, ErrShowHelp) {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		code = 1
	}
	Usage()
	os.Exit(code)
}

// Usage prints the help message for the default set.
func Usage() { fmt.Fprint(os.Stdout, std.Usage()) }
