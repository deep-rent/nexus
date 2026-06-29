package bind_test

import (
	"reflect"
	"testing"

	"github.com/deep-rent/nexus/internal/bind"
)

type mapSource map[string][]string

func (m mapSource) Lookup(key string) ([]string, bool) {
	v, ok := m[key]
	return v, ok
}

func TestBinder_Bind(t *testing.T) {
	t.Parallel()

	type Config struct {
		Host    string   `bind:"host"`
		Port    int      `bind:"port,default:8080"`
		Tags    []string `bind:"tags,split:','"`
		Missing string   `bind:"missing,required"`
	}

	b := bind.New("bind")

	t.Run("success", func(t *testing.T) {
		var cfg Config
		src := mapSource{
			"host":    {"localhost"},
			"tags":    {"a,b"},
			"missing": {"foo"},
		}

		err := b.Bind(&cfg, "", src)
		if err != nil {
			t.Fatalf("Bind() failed: %v", err)
		}

		if cfg.Host != "localhost" {
			t.Errorf("Host = %q; want 'localhost'", cfg.Host)
		}
		if cfg.Port != 8080 {
			t.Errorf("Port = %d; want 8080", cfg.Port)
		}
		if !reflect.DeepEqual(cfg.Tags, []string{"a", "b"}) {
			t.Errorf("Tags = %v; want [a b]", cfg.Tags)
		}
	})

	t.Run("missing required", func(t *testing.T) {
		var cfg Config
		src := mapSource{
			"host": {"localhost"},
		}

		err := b.Bind(&cfg, "", src)
		if err == nil {
			t.Fatal("Bind() expected error, got nil")
		}
	})

	t.Run("multiple values", func(t *testing.T) {
		type ArrayConfig struct {
			IDs []int `bind:"ids"`
		}
		var cfg ArrayConfig
		src := mapSource{
			"ids": {"1", "2", "3"},
		}

		err := b.Bind(&cfg, "", src)
		if err != nil {
			t.Fatalf("Bind() failed: %v", err)
		}

		if !reflect.DeepEqual(cfg.IDs, []int{1, 2, 3}) {
			t.Errorf("IDs = %v; want [1 2 3]", cfg.IDs)
		}
	})
}

func TestBinder_PanicOnInvalidTag(t *testing.T) {
	t.Parallel()

	defer func() {
		r := recover()
		if r == nil {
			t.Errorf("Expected panic on invalid tag, but did not panic")
		}
	}()

	type InvalidConfig struct {
		Host string `bind:"host,unknownOption:true"`
	}

	b := bind.New("bind")
	var cfg InvalidConfig
	_ = b.Bind(&cfg, "", mapSource{})
}
