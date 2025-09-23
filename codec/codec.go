package codec

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
