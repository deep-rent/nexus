package flag_test

import (
	"bytes"
	"os"
	"os/exec"
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
		abbr      rune
		full      string
		wantPanic bool
	}
	tests := []test{
		{
			name: "valid flag",
			v:    new(string),
			abbr: 's',
			full: "string",
		},
		{
			name:      "non-pointer",
			v:         "",
			abbr:      's',
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
					s.Add(tc.v, tc.abbr, tc.full, "")
				})
			} else {
				assert.NotPanics(t, func() {
					s.Add(tc.v, tc.abbr, tc.full, "")
				})
			}
		})
	}

	t.Run("duplicate short name", func(t *testing.T) {
		s := flag.New("test")
		s.Add(new(string), 'f', "foo", "")
		assert.Panics(t, func() { s.Add(new(string), 'f', "bar", "") })
	})

	t.Run("duplicate long name", func(t *testing.T) {
		s := flag.New("test")
		s.Add(new(string), 'f', "foo", "")
		assert.Panics(t, func() { s.Add(new(string), 'b', "foo", "") })
	})
}

func TestSet_Parse(t *testing.T) {
	type flags struct {
		Str     string
		Int     int
		Uint    uint
		Float64 float64
		Bool1   bool
		Bool2   bool
	}

	setup := func() (*flag.Set, *flags) {
		s := flag.New("test")
		f := &flags{Int: 99, Str: "default"}
		s.Add(&f.Str, 's', "str", "")
		s.Add(&f.Int, 'i', "int", "")
		s.Add(&f.Uint, 'u', "uint", "")
		s.Add(&f.Float64, 'f', "float64", "")
		s.Add(&f.Bool1, 'b', "bool1", "")
		s.Add(&f.Bool2, 'd', "bool2", "")
		return s, f
	}

	t.Run("short flags", func(t *testing.T) {
		s, f := setup()
		args := "-s foo -i -123 -u 456 -f 1.23 -b"
		want := flags{Str: "foo", Int: -123, Uint: 456, Float64: 1.23, Bool1: true}
		_, err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
	})

	t.Run("long flags", func(t *testing.T) {
		s, f := setup()
		args := "--str foo --int -123 --uint 456 --float64 1.23 --bool1"
		want := flags{Str: "foo", Int: -123, Uint: 456, Float64: 1.23, Bool1: true}
		_, err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
	})

	t.Run("long flags with equals", func(t *testing.T) {
		s, f := setup()
		args := "--str=foo --int=-123 --uint=456 --float64=1.23 --bool1=true"
		want := flags{Str: "foo", Int: -123, Uint: 456, Float64: 1.23, Bool1: true}
		_, err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
	})

	t.Run("grouped short bools", func(t *testing.T) {
		s, f := setup()
		args := "-bd"
		want := flags{Int: 99, Str: "default", Bool1: true, Bool2: true}
		_, err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
	})

	t.Run("grouped short bool with value", func(t *testing.T) {
		s, f := setup()
		args := "-bsfoo"
		want := flags{Int: 99, Str: "foo", Bool1: true}
		_, err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
	})

	t.Run("attached value", func(t *testing.T) {
		s, f := setup()
		args := "-i-123"
		want := flags{Int: -123, Str: "default"}
		_, err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
	})

	t.Run("defaults", func(t *testing.T) {
		s, f := setup()
		args := ""
		want := flags{Int: 99, Str: "default"}
		_, err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
	})

	t.Run("terminator", func(t *testing.T) {
		s, f := setup()
		args := "-i 1 -- -i 2"
		want := flags{Int: 1, Str: "default"}
		_, err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
	})

	t.Run("bool toggle short", func(t *testing.T) {
		s := flag.New("test")
		v := true
		s.Add(&v, 'b', "", "")
		args := "-b"
		_, err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.False(t, v, "bool flag should be toggled to false")
	})

	t.Run("bool toggle long", func(t *testing.T) {
		s := flag.New("test")
		v := true
		s.Add(&v, 0, "bool", "")
		args := "--bool"
		_, err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.False(t, v, "bool flag should be toggled to false")
	})

	t.Run("errors", func(t *testing.T) {
		tests := []struct {
			name string
			args string
		}{
			{"unknown short flag", "-x"},
			{"unknown long flag", "--unknown"},
			{"missing value for short flag", "-s"},
			{"missing value for long flag", "--str"},
			{"invalid int value", "--int abc"},
			{"invalid bool value", "--bool1=maybe"},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				s, _ := setup()
				_, err := s.Parse(strings.Fields(tc.args))
				require.Error(t, err)
			})
		}
	})

	t.Run("help flag", func(t *testing.T) {
		s := flag.New("test")
		_, err := s.Parse([]string{"--help"})
		require.Error(t, err)
		assert.ErrorIs(t, err, flag.ErrHelp)
	})
}

func TestSet_Usage(t *testing.T) {
	s := flag.New("foobar")
	var (
		port int    = 8080
		host string = "localhost"
		verb bool
	)
	s.Summary("A one-line summary of what the command does.")
	s.Add(&port, 'p', "port", "Port to listen on")
	s.Add(&host, 'h', "host", "Host address to bind to")
	s.Add(&verb, 'v', "verbose", "Enable verbose logging")

	out := s.Usage()

	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Usage() output:\n%s", out)
		}
	})

	assert.Contains(t, out, "Usage: foobar [OPTION]...")
	assert.Contains(t, out, "A one-line summary of what the command does.")
	assert.Contains(t, out, "-p, --port")
	assert.Contains(t, out, "Port to listen on (default: 8080)")
	assert.Contains(t, out, "-h, --host")
	assert.Contains(t, out, "Host address to bind to (default: localhost)")
	assert.Contains(t, out, "-v, --verbose")
	assert.Contains(t, out, "Enable verbose logging")
	assert.Contains(t, out, "--help")
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
	t.Run("success", func(t *testing.T) {
		port, host, verb := setupTestFlags()

		args := os.Args
		defer func() { os.Args = args }()

		os.Args = []string{"cmd", "-p", "9999", "--verbose", "--host=remote"}

		flag.Parse()

		assert.Equal(t, 9999, *port, "Port should be updated")
		assert.Equal(t, "remote", *host, "Host should be updated")
		assert.True(t, *verb, "Verbose flag should be set to true")
	})

	t.Run("error exit", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
		cmd.Args = append(cmd.Args, "--", "--unknown-flag")

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err, ok := cmd.Run().(*exec.ExitError)
		require.True(t, ok, "should exit with an ExitError")
		assert.Equal(t, 1, err.ExitCode(), "exit code should be 1")

		assert.Contains(t, stdout.String(),
			"Usage:", "should print help message",
		)
		assert.Contains(t, stderr.String(),
			"Error: unknown flag --unknown-flag", "should contain specific error",
		)
	})
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	args := os.Args
	for i, arg := range args {
		if arg == "--" {
			args = args[i+1:]
			break
		}
	}
	os.Args = append([]string{os.Args[0]}, args...)
	setupTestFlags()
	flag.Parse()
}
