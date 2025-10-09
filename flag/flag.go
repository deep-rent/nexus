// Package flag provides a simple, reflection-based parser for command-line
// arguments. It offers a streamlined API with support for POSIX/GNU-style flags
// and named positional arguments.
//
// # Features
//
//   - Supports POSIX-style short options (-v) and GNU-style long options
//     (--verbose).
//   - Handles grouped short options (-abc) and values attached to short options
//     (-p8080).
//   - Recognizes space or equals sign separators for long option values
//     (--port 8080, --port=8080).
//   - Allows repeatable flags that append to slice variables.
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

// flag encapsulates metadata for a single registered command-line flag.
type flag struct {
	val      reflect.Value // The reflection value of the target variable.
	def      any           // The default value, captured at registration.
	char     rune          // The shorthand form (e.g., 'v' for -v).
	name     string        // The long-form name (e.g., "verbose" for --verbose).
	desc     string        // The description shown in the help message.
	repeated bool          // True if the flag accepts multiple values.
}

// set sets the flag's value from a string, handling both single and
// repeated flags.
func (f *flag) set(v string) error {
	if f.repeated {
		return addRepeated(f.val, v)
	} else {
		return setValue(f.val, v)
	}
}

// toggle inverts a boolean flag's value from its default.
func (f *flag) toggle() {
	def, _ := f.def.(bool)
	f.val.SetBool(!def)
}

// parg encapsulates metadata for a single registered positional argument.
type parg struct {
	val      reflect.Value // The reflection value of the target variable.
	name     string        // The placeholder name (e.g., "SOURCE").
	desc     string        // The description shown in the help message.
	required bool          // True if the argument must be provided.
	variadic bool          // True if it accepts one or more values.
}

// set sets the argument's value from a string.
func (a *parg) set(v string) error { return setValue(a.val, v) }

// Set manages a collection of defined flags for a command.
type Set struct {
	cmd   string           // The command name, used for the help message.
	sum   string           // A one-line summary of the command's purpose.
	flags []*flag          // A list of all registered flags.
	char  map[rune]*flag   // A map from shorthand forms to flags.
	name  map[string]*flag // A map from long-form names to flags.
	pargs []*parg          // A list of all registered positional arguments.
}

// New creates a new, empty flag Set. The command name is used in the
// generated usage message (e.g., "Usage: <cmd> [OPTION]...").
func New(cmd string) *Set {
	return &Set{
		cmd:  cmd,
		char: make(map[rune]*flag),
		name: make(map[string]*flag),
	}
}

// Summary sets a one-line synopsis for the command, which is displayed in the
// usage message below the main usage line. If not set or empty, no summary
// will be shown.
func (s *Set) Summary(sum string) { s.sum = sum }

// Add registers a new flag with the set. It binds a command-line option to the
// variable pointed to by v. The variable's initial value is captured as its
// default.
//
// The destination v must be a pointer to a bool, float, int, string, uint, or
// complex including their sized variants (e.g., int64). If v is a slice, the
// flag can be repeated multiple times to append values in order.
//
// The char parameter is the single-letter short name (e.g., 'v' for -v), and
// can be 0 if no short name is desired. The name parameter is the long name
// (e.g., "verbose" for --verbose) and can be empty if no long name is desired.
// At least one name (char or name) must be provided.
//
// This method panics if the destination v is not a pointer to a supported type,
// if a flag with the same name is registered twice, if both char and name
// are empty, or if name contains only a single character.
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
	repeated := e.Kind() == reflect.Slice
	if repeated {
		if kind := e.Type().Elem().Kind(); !isPrimitive(kind) {
			panic(fmt.Sprintf("unsupported repeatable flag type: []%s", kind))
		}
	} else {
		if kind := e.Kind(); !isPrimitive(kind) {
			panic(fmt.Sprintf("unsupported flag type: %s", kind))
		}
	}

	f := &flag{
		val:      e,
		def:      e.Interface(), // Capture initial value as default.
		char:     char,
		name:     name,
		desc:     desc,
		repeated: repeated,
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
// pointer to a supported primitive type or, for a variadic argument, a pointer
// to a slice of a supported primitive type. The name is conventionally
// uppercase (e.g., "FILE"). A description is required for the help message.
//
// Arguments are parsed in the order they are defined. Required arguments must
// precede optional ones. A variadic argument must be the final argument and
// will consume all remaining command-line values. For a required variadic
// argument, at least one value must be provided.
//
// This method panics if argument registration rules are violated (e.g.,
// defining a required argument after an optional one).
func (s *Set) Arg(v any, name, desc string, required bool) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer {
		panic("argument destination must be a pointer")
	}

	if len(s.pargs) > 0 {
		last := s.pargs[len(s.pargs)-1]
		if last.variadic {
			panic("cannot add argument after a variadic argument")
		}
		if !last.required && required {
			panic("required arguments must be defined before optional ones")
		}
	}

	e := rv.Elem()
	variadic := e.Kind() == reflect.Slice

	if variadic {
		if kind := e.Type().Elem().Kind(); !isPrimitive(kind) {
			panic(fmt.Sprintf("unsupported variadic argument type: %s", kind))
		}
	} else {
		// For non-slices, check the kind directly.
		if kind := e.Kind(); !isPrimitive(kind) {
			panic(fmt.Sprintf("unsupported argument type: %s", kind))
		}
	}

	a := &parg{
		val:      e,
		name:     strings.ToUpper(name),
		desc:     desc,
		required: required,
		variadic: variadic,
	}
	s.pargs = append(s.pargs, a)
}

// ErrHelp is a sentinel error returned by Parse when it encounters a help flag.
// This signals to the caller that a help message should be displayed and the
// program should exit successfully.
var ErrHelp = errors.New("flag: show help")

// Parse processes command-line arguments, mapping them to their corresponding
// flags and named arguments. It returns an error if parsing fails.
//
// If named arguments are defined, Parse will attempt to satisfy them from the
// positional arguments. If there are missing, extra, or invalid arguments, it
// returns an error. Flags can be explicitly separated from positional arguments
// using the "--" terminator. If no named arguments are defined, any positional
// arguments are treated as errors.
func (s *Set) Parse(args []string) error {
	var pargs []string
	for i := 0; i < len(args); {
		arg := args[i]
		if len(arg) > 0 && arg[0] != '-' { // Positional argument
			pargs = append(pargs, arg)
			i++
			continue
		}
		if len(arg) < 2 { // Handle "-" as a positional argument
			pargs = append(pargs, arg)
			i++
			continue
		}

		var (
			k   int
			err error
		)
		if strings.HasPrefix(arg, "--") {
			if len(arg) == 2 { // End of flags marker "--"
				pargs = append(pargs, args[i+1:]...)
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
	if len(s.pargs) > 0 {
		return s.parseArgs(pargs)
	}
	// If no named arguments are defined, any positional args are an error.
	if len(pargs) > 0 {
		return fmt.Errorf("unexpected positional arguments: %v", pargs)
	}
	return nil
}

// parseArgs consumes positional arguments based on configured rules.
func (s *Set) parseArgs(pargs []string) error {
	for _, a := range s.pargs {
		if a.variadic {
			if a.required && len(pargs) == 0 {
				return fmt.Errorf("missing required argument <%s>", a.name)
			}
			if err := setVariadic(a.val, pargs); err != nil {
				return fmt.Errorf(
					"invalid value for variadic argument %s: %w", a.name, err,
				)
			}
			pargs = nil // All arguments consumed.
			break
		}

		if len(pargs) == 0 {
			if a.required {
				return fmt.Errorf("missing required argument <%s>", a.name)
			}
			break
		}
		if err := a.set(pargs[0]); err != nil {
			return fmt.Errorf("invalid value for argument %s: %w", a.name, err)
		}
		pargs = pargs[1:]
	}

	if len(pargs) > 0 {
		return fmt.Errorf("too many arguments: %v", pargs)
	}

	return nil // Success
}

// parseChar handles abbreviated flags such as -v, -abc, or -p8080.
// It returns the number of arguments consumed from the input slice and any
// error that occurred along the way.
func (s *Set) parseChar(args []string, i int) (int, error) {
	arg := args[i]
	grp := strings.TrimPrefix(arg, "-")

	for j, char := range grp {
		f := s.char[char]
		if f == nil {
			return 0, fmt.Errorf("unknown flag -%c", char)
		}

		// Handle non-slice booleans separately.
		if f.val.Kind() == reflect.Bool && !f.repeated {
			f.toggle()
			continue
		}

		// Value is attached (e.g., -p8080). It's the rest of the group.
		val := grp[j+1:]
		if val != "" {
			// Value is attached (e.g., -p8080)
			if err := f.set(val); err != nil {
				return 0, fmt.Errorf("invalid value for flag -%c: %w", char, err)
			}
			return 1, nil
		}

		// Value is the next argument.
		i++
		if i >= len(args) {
			return 0, fmt.Errorf("flag -%c requires a value", char)
		}
		if err := f.set(args[i]); err != nil {
			return 0, fmt.Errorf("invalid value for flag -%c: %w", char, err)
		}
		return 2, nil
	}

	return 1, nil
}

// parseName handles long-form flags such as --verbose or --port=8080.
// It returns the number of arguments consumed from the input slice and any
// error that occurred along the way.
func (s *Set) parseName(args []string, i int) (int, error) {
	arg := args[i]
	k, v, pair := strings.Cut(arg[2:], "=")

	f := s.name[k]
	if f == nil {
		return 0, fmt.Errorf("unknown flag --%s", k)
	}

	// Handle boolean flags, which don't require a value.
	if f.val.Kind() == reflect.Bool && !f.repeated {
		f.toggle()
		// Allow explicit override like --verbose=false.
		if pair {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return 0, fmt.Errorf("expected bool for flag --%s, got %q", k, v)
			}
			f.val.SetBool(b)
		}
		return 1, nil
	}

	if !pair {
		i++
		if i >= len(args) {
			return 0, fmt.Errorf("flag --%s requires a value", k)
		}
		v = args[i]
	}
	if err := f.set(v); err != nil {
		return 0, fmt.Errorf("invalid value for flag --%s: %w", k, err)
	}
	if pair {
		return 1, nil
	}
	return 2, nil
}

// Parse attempts to convert string v to the type expected by rv and sets it.
//
// Preconditions:
// 1. rv must be a valid reflect.Value (rv.IsValid() == true).
// 2. rv must be settable (rv.CanSet() == true).
// 3. rv must have a Kind for which Is(rv.Kind()) returns true.
//
// Failure to satisfy these preconditions will result in a runtime panic or
// an error.
func setValue(rv reflect.Value, v string) error {
	switch kind := rv.Kind(); kind {
	case reflect.String:
		rv.SetString(v)
		return nil
	case reflect.Bool:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("%q is not a bool", v)
		}
		rv.SetBool(b)
		return nil
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
		return nil
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
		return nil
	case reflect.Float32, reflect.Float64:
		b := rv.Type().Bits()
		f, err := strconv.ParseFloat(v, b)
		if err != nil {
			return fmt.Errorf("%q is not a float%d", v, b)
		}
		rv.SetFloat(f)
		return nil
	case reflect.Complex64, reflect.Complex128:
		b := rv.Type().Bits()
		c, err := strconv.ParseComplex(v, b)
		if err != nil {
			return fmt.Errorf("%q is not a complex%d", v, b)
		}
		rv.SetComplex(c)
		return nil
	default:
		return fmt.Errorf("unsupported type: %s", kind)
	}
}

// addRepeated parses and appends a repeated flag value to a slice.
func addRepeated(rv reflect.Value, v string) error {
	item := reflect.New(rv.Type().Elem()).Elem()
	if err := setValue(item, v); err != nil {
		return err
	}
	rv.Set(reflect.Append(rv, item))
	return nil
}

// setVariadic populates a slice with variadic argument values.
func setVariadic(rv reflect.Value, vs []string) error {
	// Clear the slice first, in case it had default values from registration.
	rv.Set(reflect.MakeSlice(rv.Type(), 0, len(vs)))
	for i, v := range vs {
		if err := addRepeated(rv, v); err != nil {
			return fmt.Errorf("invalid variadic argument at index %d: %w", i, err)
		}
	}
	return nil
}

// Usage generates a formatted help message detailing all registered flags and
// arguments. The output includes the command summary, argument descriptions,
// and a list of options with their descriptions and default values (if not
// the zero value for their type).
func (s *Set) Usage() string {
	var b strings.Builder

	// Build the main usage line, including named arguments.
	var args []string
	for _, a := range s.pargs {
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

	if len(s.pargs) > 0 {
		fmt.Fprint(&b, "Arguments:\n")
		for _, a := range s.pargs {
			fmt.Fprintf(w, "  %s\t%s\n", a.name, a.desc)
		}
		w.Flush() // Align both, the argument and the option columns
		fmt.Fprint(&b, "\n")
	}

	fmt.Fprintf(&b, "Options:\n")

	// Add the implicit --help flag for documentation.
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
		if f.repeated {
			desc += " (repeatable)"
		}
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

// commandLine is the default, package-level flag Set. The top-level functions
// such as Add, Arg, Parse and so forth operate on this instance.
var commandLine *Set

func init() { Reset() }

// Summary sets the command summary on the default Set.
func Summary(sum string) { commandLine.Summary(sum) }

// Add registers a flag with the default Set.
func Add(v any, char rune, name, desc string) {
	commandLine.Add(v, char, name, desc)
}

// Arg registers a positional argument with the default Set.
func Arg(v any, name, desc string, required bool) {
	commandLine.Arg(v, name, desc, required)
}

// Parse processes command-line arguments from os.Args[1:] based on the
// default Set.
//
// On a parsing error, it prints an error message and the usage help to
// standard error, then exits the program with a non-zero status code. If the
// --help flag is used, it prints the usage help to standard output and exits
// with a zero status code.
func Parse() {
	err := commandLine.Parse(os.Args[1:])
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
	fmt.Fprint(w, commandLine.Usage())
	os.Exit(code)
}

// Usage prints the help message for the default Set to standard output.
// See (*Set).Usage for more details.
func Usage() { fmt.Fprint(os.Stdout, commandLine.Usage()) }

// Reset discards all flags and arguments that have been defined on the default
// Set. This is intended for use in tests to ensure a clean state.
func Reset() {
	commandLine = New(filepath.Base(os.Args[0]))
}

// isPrimitive reports whether the specified kind is a primitive type.
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
		reflect.Float64,
		reflect.Complex64,
		reflect.Complex128:
		return true
	}
	return false
}
