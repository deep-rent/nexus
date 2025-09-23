package config

import (
	"os"

	"github.com/deep-rent/nexus/codec"
)

func Load(path string, v any) error {
	codec, err := codec.Infer(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return codec.Decode(data, v)
}

func Save(path string, v any) error {
	codec, err := codec.Infer(path)
	if err != nil {
		return err
	}
	data, err := codec.Encode(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
