package flag_test

import (
	"bytes"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/flag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSet_Add(t *testing.T) {
	type test struct {
		name      string
		v         any
		char      rune
		full      string
		wantPanic bool
	}
	tests := []test{
		{
			name: "valid flag",
			v:    new(string),
			char: 's',
			full: "string",
		},
		{
			name: "valid repeated flag",
			v:    new([]string),
			char: 'r',
			full: "repeated",
		},
		{
			name:      "non-pointer",
			v:         "",
			char:      's',
			wantPanic: true,
		},
		{
			name:      "unnamed",
			v:         new(string),
			wantPanic: true,
		},
		{
			name:      "single-letter name",
			v:         new(string),
			full:      "x",
			wantPanic: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := flag.New("test")
			if tc.wantPanic {
				assert.Panics(t, func() {
					s.Add(tc.v, tc.char, tc.full, "")
				})
			} else {
				assert.NotPanics(t, func() {
					s.Add(tc.v, tc.char, tc.full, "")
				})
			}
		})
	}

	t.Run("duplicate short name", func(t *testing.T) {
		s := flag.New("test")
		s.Add(new(string), 'f', "foo", "")
		assert.Panics(t, func() {
			s.Add(new(string), 'f', "bar", "")
		})
	})

	t.Run("duplicate long name", func(t *testing.T) {
		s := flag.New("test")
		s.Add(new(string), 'f', "foo", "")
		assert.Panics(t, func() {
			s.Add(new(string), 'b', "foo", "")
		})
	})

	t.Run("unsupported repeated flag type", func(t *testing.T) {
		s := flag.New("test")
		type Unsupported struct{}
		assert.Panics(t, func() {
			s.Add(new([]Unsupported), 'u', "unsupported", "")
		})
	})
}

func TestSet_Arg(t *testing.T) {
	t.Run("valid args", func(t *testing.T) {
		s := flag.New("test")
		assert.NotPanics(t, func() {
			s.Arg(new(string), "REQ", "", true)
			s.Arg(new(string), "OPT", "", false)
			s.Arg(new([]string), "VAR", "", false)
		})
	})

	t.Run("panics", func(t *testing.T) {
		tests := []struct {
			name string
			prep func(*flag.Set)
		}{
			{
				"non-pointer",
				func(s *flag.Set) { s.Arg("", "A", "", true) },
			},
			{
				"required after optional",
				func(s *flag.Set) {
					s.Arg(new(string), "OPT", "", false)
					s.Arg(new(string), "REQ", "", true)
				},
			},
			{
				"arg after variadic",
				func(s *flag.Set) {
					s.Arg(new([]string), "VAR", "", false)
					s.Arg(new(string), "OTHER", "", false)
				},
			},
			{
				"unsupported type",
				func(s *flag.Set) {
					type Unsupported struct{}
					s.Arg(new(Unsupported), "ANY", "", false)
				},
			},
			{
				"unsupported variadic type",
				func(s *flag.Set) {
					type Unsupported struct{}
					s.Arg(new([]Unsupported), "VAR", "", false)
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				s := flag.New("test")
				assert.Panics(t, func() { tc.prep(s) })
			})
		}
	})
}

func TestSet_Parse(t *testing.T) {
	t.Run("short flags", func(t *testing.T) {
		s := flag.New("test")
		var str string
		var i int
		s.Add(&str, 's', "str", "")
		s.Add(&i, 'i', "int", "")

		err := s.Parse(strings.Fields("-s foo -i -123"))
		require.NoError(t, err)
		assert.Equal(t, "foo", str)
		assert.Equal(t, -123, i)
	})

	t.Run("long flags", func(t *testing.T) {
		s := flag.New("test")
		var str string
		var i int
		s.Add(&str, 's', "str", "")
		s.Add(&i, 'i', "int", "")

		err := s.Parse(strings.Fields("--str foo --int -123"))
		require.NoError(t, err)
		assert.Equal(t, "foo", str)
		assert.Equal(t, -123, i)
	})

	t.Run("long flags with equals sign", func(t *testing.T) {
		s := flag.New("test")
		var str string
		var b bool
		s.Add(&str, 's', "str", "")
		s.Add(&b, 'b', "bool", "")

		err := s.Parse(strings.Fields("--str=foo --bool=true"))
		require.NoError(t, err)
		assert.Equal(t, "foo", str)
		assert.True(t, b)
	})

	t.Run("grouped short bool flags", func(t *testing.T) {
		s := flag.New("test")
		var b1, b2 bool
		s.Add(&b1, 'a', "", "")
		s.Add(&b2, 'b', "", "")

		err := s.Parse(strings.Fields("-ab"))
		require.NoError(t, err)
		assert.True(t, b1)
		assert.True(t, b2)
	})

	t.Run("grouped short flags with attached value", func(t *testing.T) {
		s := flag.New("test")
		var b bool
		var str string
		s.Add(&b, 'b', "", "")
		s.Add(&str, 's', "", "")

		err := s.Parse(strings.Fields("-bsfoo"))
		require.NoError(t, err)
		assert.True(t, b)
		assert.Equal(t, "foo", str)
	})

	t.Run("repeated flags", func(t *testing.T) {
		t.Run("multiple long and short flags", func(t *testing.T) {
			s := flag.New("test")
			var hosts []string
			var ports []int
			s.Add(&hosts, 'h', "host", "")
			s.Add(&ports, 'p', "port", "")

			err := s.Parse(strings.Fields("-h host1 --host host2 --port=80 -p8080"))
			require.NoError(t, err)
			assert.Equal(t, []string{"host1", "host2"}, hosts)
			assert.Equal(t, []int{80, 8080}, ports)
		})

		t.Run("appends to default values", func(t *testing.T) {
			s := flag.New("test")
			var hosts = []string{"default.host.com"}
			s.Add(&hosts, 'h', "host", "")

			err := s.Parse(strings.Fields("-h another.host.com"))
			require.NoError(t, err)
			assert.Equal(t, []string{"default.host.com", "another.host.com"}, hosts)
		})

		t.Run("no values provided", func(t *testing.T) {
			s := flag.New("test")
			var hosts []string
			s.Add(&hosts, 'h', "host", "")

			err := s.Parse([]string{})
			require.NoError(t, err)
			assert.Nil(t, hosts)
		})
	})

	t.Run("terminator", func(t *testing.T) {
		s := flag.New("test")
		var i int
		var remainder []string
		s.Add(&i, 'i', "", "")
		s.Arg(&remainder, "REMAINDER", "", false)

		err := s.Parse(strings.Fields("-i 1 -- -i 2"))
		require.NoError(t, err)

		assert.Equal(t, 1, i)
		assert.Equal(t, []string{"-i", "2"}, remainder)
	})

	t.Run("bool toggle", func(t *testing.T) {
		s := flag.New("test")
		v := true
		s.Add(&v, 'b', "bool", "")

		err := s.Parse(strings.Fields("-b"))
		require.NoError(t, err)
		assert.False(t, v, "bool flag should be toggled to false")
	})

	t.Run("required args", func(t *testing.T) {
		s := flag.New("test")
		var a, b string
		s.Arg(&a, "A", "", true)
		s.Arg(&b, "B", "", true)

		err := s.Parse(strings.Fields("foo bar"))
		require.NoError(t, err)
		assert.Equal(t, "foo", a)
		assert.Equal(t, "bar", b)
	})

	t.Run("optional args", func(t *testing.T) {
		t.Run("provided", func(t *testing.T) {
			s := flag.New("test")
			var a, b string
			s.Arg(&a, "A", "", true)
			s.Arg(&b, "B", "", false)

			err := s.Parse(strings.Fields("foo bar"))
			require.NoError(t, err)
			assert.Equal(t, "foo", a)
			assert.Equal(t, "bar", b)
		})
		t.Run("omitted", func(t *testing.T) {
			s := flag.New("test")
			var a, b string
			s.Arg(&a, "A", "", true)
			s.Arg(&b, "B", "", false)

			err := s.Parse(strings.Fields("foo"))
			require.NoError(t, err)
			assert.Equal(t, "foo", a)
			assert.Equal(t, "", b)
		})
	})

	t.Run("variadic args", func(t *testing.T) {
		t.Run("multiple values", func(t *testing.T) {
			s := flag.New("test")
			var v []string
			s.Arg(&v, "V", "", false)

			err := s.Parse(strings.Fields("a b c"))
			require.NoError(t, err)
			assert.Equal(t, []string{"a", "b", "c"}, v)
		})
		t.Run("zero values", func(t *testing.T) {
			s := flag.New("test")
			var v []string
			s.Arg(&v, "V", "", false)

			err := s.Parse(nil)
			require.NoError(t, err)
			assert.Empty(t, v)
		})
	})

	t.Run("required variadic args", func(t *testing.T) {
		t.Run("success with one value", func(t *testing.T) {
			s := flag.New("test")
			var v []string
			s.Arg(&v, "V", "", true)

			err := s.Parse([]string{"a"})
			require.NoError(t, err)
			assert.Equal(t, []string{"a"}, v)
		})

		t.Run("success with multiple values", func(t *testing.T) {
			s := flag.New("test")
			var v []string
			s.Arg(&v, "V", "", true)

			err := s.Parse([]string{"a", "b", "c"})
			require.NoError(t, err)
			assert.Equal(t, []string{"a", "b", "c"}, v)
		})

		t.Run("error with zero values", func(t *testing.T) {
			s := flag.New("test")
			var v []string
			s.Arg(&v, "V", "", true)

			err := s.Parse(nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "missing required argument <V>")
		})
	})

	t.Run("mixed flags and args", func(t *testing.T) {
		s := flag.New("test")
		var verbose bool
		var foo, bar string
		s.Add(&verbose, 'v', "verbose", "")
		s.Arg(&foo, "FOO", "", true)
		s.Arg(&bar, "BAR", "", true)

		err := s.Parse(strings.Fields("-v foo bar"))
		require.NoError(t, err)
		assert.True(t, verbose)
		assert.Equal(t, "foo", foo)
		assert.Equal(t, "bar", bar)
	})

	t.Run("errors", func(t *testing.T) {
		tests := []struct {
			name string
			prep func(*flag.Set)
			args string
		}{
			{
				"unknown short flag",
				func(s *flag.Set) {}, "-x",
			},
			{
				"unknown long flag",
				func(s *flag.Set) {}, "--unknown",
			},
			{
				"missing value for flag",
				func(s *flag.Set) { s.Add(new(string), 's', "", "") }, "-s",
			},
			{
				"invalid int value",
				func(s *flag.Set) { s.Add(new(int), 'i', "", "") }, "-i 1a",
			},
			{
				"missing required arg",
				func(s *flag.Set) { s.Arg(new(string), "A", "", true) },
				"",
			},
			{
				"too many args",
				func(s *flag.Set) { s.Arg(new(string), "A", "", true) },
				"a b",
			},
			{
				"invalid arg value",
				func(s *flag.Set) { s.Arg(new(int), "A", "", true) },
				"abc",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				s := flag.New("test")
				tc.prep(s)
				err := s.Parse(strings.Fields(tc.args))
				require.Error(t, err)
			})
		}
	})

	t.Run("help flag", func(t *testing.T) {
		s := flag.New("test")
		err := s.Parse([]string{"--help"})
		require.ErrorIs(t, err, flag.ErrHelp)
	})

	t.Run("interspersed flags and args", func(t *testing.T) {
		s := flag.New("test")
		var verbose bool
		var foo, bar string
		s.Add(&verbose, 'v', "verbose", "")
		s.Arg(&foo, "FOO", "", true)
		s.Arg(&bar, "BAR", "", true)

		err := s.Parse([]string{"foo", "-v", "bar"})
		require.NoError(t, err)

		assert.True(t, verbose)
		assert.Equal(t, "foo", foo)
		assert.Equal(t, "bar", bar)
	})

	t.Run("empty string value for flag", func(t *testing.T) {
		s := flag.New("test")
		var str = "default"
		s.Add(&str, 's', "str", "")

		err := s.Parse([]string{"--str", ""})
		require.NoError(t, err)
		assert.Equal(t, "", str)
	})

	t.Run("hyphen as positional argument", func(t *testing.T) {
		s := flag.New("test")
		var a, b string
		s.Arg(&a, "A", "", true)
		s.Arg(&b, "B", "", true)

		err := s.Parse([]string{"-", "foo"})
		require.NoError(t, err)
		assert.Equal(t, "-", a)
		assert.Equal(t, "foo", b)
	})

	t.Run("integer arg", func(t *testing.T) {
		s := flag.New("test")
		var num int
		s.Arg(&num, "NUM", "", true)

		err := s.Parse(strings.Fields("-- -20"))
		require.NoError(t, err)
		assert.Equal(t, -20, num)
	})

	t.Run("variadic integer args", func(t *testing.T) {
		s := flag.New("test")
		var nums []int
		s.Arg(&nums, "NUMS", "", false)

		err := s.Parse(strings.Fields("-- 10 -20 30"))
		require.NoError(t, err)
		assert.Equal(t, []int{10, -20, 30}, nums)
	})
}

func TestSet_Usage(t *testing.T) {
	t.Run("flags only", func(t *testing.T) {
		s := flag.New("foobar")
		var port int = 8080
		var host string = "localhost"
		s.Summary("A one-line summary.")
		s.Add(&port, 'p', "port", "Port to listen on")
		s.Add(&host, 'h', "host", "Host address to bind to")

		out := s.Usage()
		assert.Contains(t, out, "Usage: foobar [OPTION]...")
		assert.Contains(t, out, "A one-line summary.")
		assert.Contains(t, out, "-p, --port")
		assert.NotContains(t, out, "Arguments:")
	})

	t.Run("mixed flags and args", func(t *testing.T) {
		s := flag.New("test")
		var (
			foo string
			bar string
			baz bool
			qux []string
		)
		s.Summary("Does something.")
		s.Add(&baz, 'b', "baz", "Baz description")
		s.Arg(&foo, "foo", "Foo description", true)
		s.Arg(&bar, "bar", "Bar description", true)
		s.Arg(&qux, "qux", "Qux description", false)

		out := s.Usage()
		assert.Contains(t, out, "Usage: test [OPTION]... <FOO> <BAR> [QUX]...")
		assert.Contains(t, out, "Does something.")
		assert.Contains(t, out, "Arguments:")
		assert.Regexp(t, regexp.MustCompile(`FOO\s+Foo description`), out)
		assert.Regexp(t, regexp.MustCompile(`BAR\s+Bar description`), out)
		assert.Regexp(t, regexp.MustCompile(`QUX\s+Qux description`), out)
		assert.Contains(t, out, "Options:")
		assert.Contains(t, out, "-b, --baz")
	})

	t.Run("repeated flag usage", func(t *testing.T) {
		s := flag.New("test")
		var hosts = []string{"default.host"}
		s.Add(&hosts, 'h', "host", "Host to connect to")

		out := s.Usage()
		assert.Contains(t, out, "(repeatable)")
	})

	t.Run("usage with bool default true", func(t *testing.T) {
		s := flag.New("test")
		var enabled = true
		s.Add(&enabled, 'e', "enabled", "Is enabled")

		out := s.Usage()
		assert.Contains(t, out, "(default: true)")
	})
}

func setupTestFlags() (*int, *string, *bool) {
	flag.Summary("A test command.")

	p := 1234
	h := "localhost"
	v := false

	flag.Add(&p, 'p', "port", "Port to listen on")
	flag.Add(&h, 'h', "host", "Host address to bind to")
	flag.Add(&v, 'v', "verbose", "Enable verbose logging")

	return &p, &h, &v
}

func TestParse(t *testing.T) {
	if sub := os.Getenv("GO_TEST_SUBPROCESS_NAME"); sub != "" {
		switch sub {
		case "error exit":
			os.Args = []string{os.Args[0], "--unknown-flag"}
			setupTestFlags()
			flag.Parse()
		case "usage exit":
			os.Args = []string{os.Args[0], "--help"}
			setupTestFlags()
			flag.Parse()
		}
		return
	}

	t.Run("success", func(t *testing.T) {
		defer flag.Reset()
		port, host, verb := setupTestFlags()

		original := os.Args
		defer func() { os.Args = original }()
		os.Args = []string{"cmd", "-p", "9999", "--verbose", "--host=remote"}

		flag.Parse()

		assert.Equal(t, 9999, *port, "Port should be updated")
		assert.Equal(t, "remote", *host, "Host should be updated")
		assert.True(t, *verb, "Verbose flag should be set to true")
	})

	t.Run("error exit", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestParse$")
		cmd.Env = append(os.Environ(), "GO_TEST_SUBPROCESS_NAME=error exit")

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		err := cmd.Run()
		exitErr, ok := err.(*exec.ExitError)
		require.True(t, ok, "command should exit with an error")
		assert.Equal(t, 1, exitErr.ExitCode(), "exit code should be 1")

		out := stderr.String()

		assert.Contains(t, out, "Error:", "should contain specific error")
		assert.Contains(t, out, "Usage:", "should print help message to stderr")
	})

	t.Run("usage exit", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestParse$")
		cmd.Env = append(os.Environ(), "GO_TEST_SUBPROCESS_NAME=usage exit")

		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		err := cmd.Run()

		require.NoError(t, err, "process should exit cleanly with code 0")

		out := stdout.String()
		assert.Contains(t, out, "Usage:", "should print help message to stdout")
	})
}
