package codec

import (
	"github.com/goccy/go-json"
	"github.com/goccy/go-yaml"
)

type Decoder interface {
	Decode(data []byte, v any) error
}

type Encoder interface {
	Encode(v any) ([]byte, error)
}

type Codec interface {
	Decoder
	Encoder
}

type jsonCodec struct{}

func (jsonCodec) Decode(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (jsonCodec) Encode(v any) ([]byte, error) {
	return json.Marshal(v)
}

type yamlCodec struct{}

func (yamlCodec) Decode(data []byte, v any) error {
	return yaml.Unmarshal(data, v)
}

func (yamlCodec) Encode(v any) ([]byte, error) {
	return yaml.Marshal(v)
}

func Infer(path string) Codec {
	return jsonCodec{}
}
