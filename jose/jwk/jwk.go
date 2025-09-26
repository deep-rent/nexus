package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/deep-rent/nexus/jose/jwa"
)

type Key interface {
	Algorithm() string
	ID() string
	Thumbprint() string
	Verify(msg, sig []byte) bool
}

type key struct {
	verifier jwa.Verifier
	kid      string
	x5t      string
}

func (k *key) Algorithm() string  { return k.verifier.Algorithm() }
func (k *key) ID() string         { return k.kid }
func (k *key) Thumbprint() string { return k.x5t }
func (k *key) Verify(msg, sig []byte) bool {
	return k.verifier.Verify(msg, sig)
}

var _ Key = &key{}

type Set interface {
	Lookup(h map[string]any) Key
}

type probe map[string]json.RawMessage

func (p probe) Req(k string) (string, error) {
	v, ok := p[k]
	if !ok {
		return "", fmt.Errorf("missing %s", k)
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", fmt.Errorf("invalid %s: %w", k, err)
	}
	return s, nil
}

func (p probe) Opt(k string) (string, error) {
	v, ok := p[k]
	if !ok {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", fmt.Errorf("invalid %s: %w", k, err)
	}
	return s, nil
}

func (p probe) Base64(k string) ([]byte, error) {
	s, err := p.Req(k)
	if err != nil {
		return nil, err
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", k, err)
	}
	return b, nil
}

func (p probe) BigInt(k string) (*big.Int, error) {
	b, err := p.Base64(k)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func (p probe) Parse() (Key, error) {
	use, err := p.Opt("use")
	if err != nil {
		return nil, err
	}
	if use != "sig" {
		return nil, errors.New("unsupported key use") // non-fatal
	}
	kty, err := p.Req("kty")
	if err != nil {
		return nil, err
	}
	alg, err := p.Opt("alg")
	if err != nil || alg == "" {
		return nil, errors.New("algorithm not defined") // non-fatal
	}
	kid, err := p.Opt("kid")
	if err != nil {
		return nil, err
	}
	x5t, err := p.Opt("x5t#S256")
	if err != nil {
		return nil, err
	}
	if kid == "" && x5t == "" {
		return nil, errors.New("unidentified key") // non-fatal
	}

	parse, ok := parsers[kty]
	if !ok {
		return nil, fmt.Errorf("unsupported key type: %s", kty) // non-fatal
	}

	v, err := parse(p, alg)
	if err != nil {
		return nil, err
	}
	return &key{verifier: v, kid: kid, x5t: x5t}, nil
}

type parser func(p probe, alg string) (jwa.Verifier, error)

var parsers = map[string]parser{
	"RSA": func(p probe, alg string) (jwa.Verifier, error) {
		n, err := p.BigInt("n")
		if err != nil {
			return nil, err
		}
		b, err := p.Base64("e")
		if err != nil {
			return nil, err
		}
		var e int
		for _, i := range b {
			e = (e << 8) | int(i)
		}
		var scheme jwa.Scheme[*rsa.PublicKey]
		switch alg {
		case "RS256":
			scheme = jwa.RS256
		case "RS384":
			scheme = jwa.RS384
		case "RS512":
			scheme = jwa.RS512
		case "PS256":
			scheme = jwa.PS256
		case "PS384":
			scheme = jwa.PS384
		case "PS512":
			scheme = jwa.PS512
		default:
			return nil, fmt.Errorf("unsupported RSA algorithm: %s", alg) // non-fatal
		}
		key := &rsa.PublicKey{N: n, E: e}
		return jwa.NewVerifier(scheme, key), nil
	},
	"EC": func(p probe, alg string) (jwa.Verifier, error) {
		crv, err := p.Req("crv")
		if err != nil {
			return nil, err
		}

		var c elliptic.Curve
		var scheme jwa.Scheme[*ecdsa.PublicKey]
		switch crv {
		case "P-256":
			c, scheme = elliptic.P256(), jwa.ES256
		case "P-384":
			c, scheme = elliptic.P384(), jwa.ES384
		case "P-521":
			c, scheme = elliptic.P521(), jwa.ES512
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", crv) // non-fatal
		}
		if alg != scheme.Name() {
			return nil, fmt.Errorf("algorithm %s does not match curve %s", alg, crv)
		}
		x, err := p.BigInt("x")
		if err != nil {
			return nil, err
		}
		y, err := p.BigInt("y")
		if err != nil {
			return nil, err
		}
		key := &ecdsa.PublicKey{Curve: c, X: x, Y: y}
		return jwa.NewVerifier(scheme, key), nil
	},
	"OKP": func(p probe, alg string) (jwa.Verifier, error) {
		crv, err := p.Req("crv")
		if err != nil {
			return nil, err
		}
		x, err := p.Base64("x")
		if err != nil {
			return nil, err
		}
		switch crv {
		case "Ed25519":
			if len(x) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("wrong %s key size (%d)", crv, len(x))
			}
			scheme := jwa.Ed25519
			if alg != scheme.Name() {
				return nil, fmt.Errorf("algorithm %s does not match curve %s", alg, crv)
			}
			key := ed25519.PublicKey(x)
			return jwa.NewVerifier(scheme, key), nil
		case "Ed448":
			if len(x) != ed448.PublicKeySize {
				return nil, fmt.Errorf("wrong %s key size (%d)", crv, len(x))
			}
			scheme := jwa.Ed448
			if alg != scheme.Name() {
				return nil, fmt.Errorf("algorithm %s does not match curve %s", alg, crv)
			}
			key := ed448.PublicKey(x)
			return jwa.NewVerifier(scheme, key), nil
		default:
			return nil, fmt.Errorf("unsupported OKP curve: %s", crv) // non-fatal
		}
	},
}
