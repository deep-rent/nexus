package config

import (
	"os"

	"github.com/deep-rent/nexus/codec"
)

func Load(path string, v any) error {
	dec, err := codec.Infer(path)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return dec.Decode(raw, v)
}

func Save(path string, v any) error {
	enc, err := codec.Infer(path)
	if err != nil {
		return err
	}
	raw, err := enc.Encode(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0644)
}
