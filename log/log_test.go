package log_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/deep-rent/nexus/log"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	type test struct {
		name string
		opts []log.Option
	}

	tests := []test{
		{
			name: "no options",
			opts: []log.Option{},
		},
		{
			name: "with level string",
			opts: []log.Option{log.WithLevel("debug")},
		},
		{
			name: "with level const",
			opts: []log.Option{log.WithLevel(slog.LevelError)},
		},
		{
			name: "with format string",
			opts: []log.Option{log.WithFormat("json")},
		},
		{
			name: "with format const",
			opts: []log.Option{log.WithFormat(log.FormatJSON)},
		},
		{
			name: "with add source",
			opts: []log.Option{log.WithAddSource(true)},
		},
		{
			name: "with writer",
			opts: []log.Option{log.WithWriter(new(bytes.Buffer))},
		},
		{
			name: "with nil writer",
			opts: []log.Option{log.WithWriter(nil)},
		},
		{
			name: "all options",
			opts: []log.Option{
				log.WithLevel("debug"),
				log.WithFormat("json"),
				log.WithAddSource(true),
				log.WithWriter(new(bytes.Buffer)),
			},
		},
		{
			name: "invalid level",
			opts: []log.Option{log.WithLevel("foo")},
		},
		{
			name: "invalid format",
			opts: []log.Option{log.WithFormat("bar")},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.NotNil(t, log.New(tc.opts...))
		})
	}
}

func TestParseLevel(t *testing.T) {
	type test struct {
		in      string
		want    slog.Level
		wantErr bool
	}

	tests := []test{
		{"debug", slog.LevelDebug, false},
		{"info", slog.LevelInfo, false},
		{"warn", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"DEBUG", slog.LevelDebug, false},
		{"INFO", slog.LevelInfo, false},
		{"Warn", slog.LevelWarn, false},
		{"Error", slog.LevelError, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := log.ParseLevel(tc.in)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestParseFormat(t *testing.T) {
	type test struct {
		in      string
		want    log.Format
		wantErr bool
	}

	tests := []test{
		{"text", log.FormatText, false},
		{"json", log.FormatJSON, false},
		{"TEXT", log.FormatText, false},
		{"JSON", log.FormatJSON, false},
		{"Text", log.FormatText, false},
		{"Json", log.FormatJSON, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := log.ParseFormat(tc.in)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestFormatString(t *testing.T) {
	type test struct {
		in   log.Format
		want string
	}

	tests := []test{
		{log.FormatText, "text"},
		{log.FormatJSON, "json"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.in.String())
		})
	}
}
