package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

type Params map[string]any

func (p Params) String(k string) (string, bool) {
	v, ok := p[k]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

type Header Params
type Claims Params

type Token struct {
	Header Header
	Claims Claims
}

type SignedToken struct {
	Token

	Signature []byte
}

func Parse(raw string) (*SignedToken, error) {
	i, j := strings.Index(raw, "."), strings.LastIndex(raw, ".")
	if i < 0 || i == j {
		return nil, nil
	}

	h, err := decode(raw[:i])
	if err != nil {
		return nil, err
	}

	c, err := decode(raw[i+1 : j])
	if err != nil {
		return nil, err
	}

	s, err := decode(raw[j+1:])
	if err != nil {
		return nil, err
	}

	var header Header
	if err := json.Unmarshal(h, &header); err != nil {
		return nil, err
	}

	var claims Claims
	if err := json.Unmarshal(c, &claims); err != nil {
		return nil, err
	}

	token := Token{
		Header: header,
		Claims: claims,
	}

	return &SignedToken{
		Token:     token,
		Signature: s,
	}, nil
}

func decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
