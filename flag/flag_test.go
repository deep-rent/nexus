package flag_test

import (
	"strings"
	"testing"

	"github.com/deep-rent/nexus/flag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdd(t *testing.T) {
	type test struct {
		name      string
		v         any
		short     string
		long      string
		wantPanic bool
	}
	tests := []test{
		{
			name:  "valid flag",
			v:     new(string),
			short: "s",
			long:  "string",
		},
		{
			name:      "not a pointer",
			v:         "",
			short:     "s",
			wantPanic: true,
		},
		{
			name:      "no name",
			v:         new(string),
			wantPanic: true,
		},
		{
			name:      "long short name",
			v:         new(string),
			short:     "long",
			wantPanic: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := flag.New("test")
			if tc.wantPanic {
				assert.Panics(t, func() {
					s.Add(tc.v, tc.short, tc.long, "")
				})
			} else {
				assert.NotPanics(t, func() {
					s.Add(tc.v, tc.short, tc.long, "")
				})
			}
		})
	}
}

func TestParse(t *testing.T) {
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
		s.Add(&f.Str, "s", "str", "")
		s.Add(&f.Int, "i", "int", "")
		s.Add(&f.Uint, "u", "uint", "")
		s.Add(&f.Float64, "f", "float64", "")
		s.Add(&f.Bool1, "b", "bool1", "")
		s.Add(&f.Bool2, "d", "bool2", "")
		return s, f
	}

	t.Run("short flags", func(t *testing.T) {
		s, f := setup()
		args := "-s foo -i -123 -u 456 -f 1.23 -b"
		want := flags{Str: "foo", Int: -123, Uint: 456, Float64: 1.23, Bool1: true}
		err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
	})

	t.Run("long flags", func(t *testing.T) {
		s, f := setup()
		args := "--str foo --int -123 --uint 456 --float64 1.23 --bool1"
		want := flags{Str: "foo", Int: -123, Uint: 456, Float64: 1.23, Bool1: true}
		err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
	})

	t.Run("long flags with equals", func(t *testing.T) {
		s, f := setup()
		args := "--str=foo --int=-123 --uint=456 --float64=1.23 --bool1=true"
		want := flags{Str: "foo", Int: -123, Uint: 456, Float64: 1.23, Bool1: true}
		err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
	})

	t.Run("grouped short bools", func(t *testing.T) {
		s, f := setup()
		args := "-bd"
		want := flags{Int: 99, Str: "default", Bool1: true, Bool2: true}
		err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
	})

	t.Run("grouped short bool with value", func(t *testing.T) {
		s, f := setup()
		args := "-bsfoo"
		want := flags{Int: 99, Str: "foo", Bool1: true}
		err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
	})

	t.Run("attached value", func(t *testing.T) {
		s, f := setup()
		args := "-i-123"
		want := flags{Int: -123, Str: "default"}
		err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
	})

	t.Run("defaults", func(t *testing.T) {
		s, f := setup()
		args := ""
		want := flags{Int: 99, Str: "default"}
		err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
	})

	t.Run("terminator", func(t *testing.T) {
		s, f := setup()
		args := "-i 1 -- -i 2"
		want := flags{Int: 1, Str: "default"}
		err := s.Parse(strings.Fields(args))
		require.NoError(t, err)
		assert.Equal(t, want, *f)
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
				err := s.Parse(strings.Fields(tc.args))
				require.Error(t, err)
			})
		}
	})

	t.Run("help flag", func(t *testing.T) {
		s := flag.New("test")
		err := s.Parse([]string{"--help"})
		require.Error(t, err)
		assert.ErrorIs(t, err, flag.ErrShowHelp)
	})
}

func TestUsage(t *testing.T) {
	s := flag.New("foobar")
	var (
		port int    = 8080
		host string = "localhost"
		verb bool
	)
	s.Summary("A one-line summary of what the command does.")
	s.Add(&port, "p", "port", "Port to listen on")
	s.Add(&host, "h", "host", "Host address to bind to")
	s.Add(&verb, "v", "verbose", "Enable verbose logging")

	out := s.Usage()

	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Usage() output:\n%s", out)
		}
	})

	assert.Contains(t, out, "Usage: foobar [OPTION]...")
	assert.Contains(t, out, "A one-line summary of what the command does.")
	assert.Contains(t, out, "-p, --port [int]")
	assert.Contains(t, out, "Port to listen on (default: 8080)")
	assert.Contains(t, out, "-h, --host [string]")
	assert.Contains(t, out, "Host address to bind to (default: localhost)")
	assert.Contains(t, out, "-v, --verbose")
	assert.Contains(t, out, "Enable verbose logging")
	assert.Contains(t, out, "--help")
}
