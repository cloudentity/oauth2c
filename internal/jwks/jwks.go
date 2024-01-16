package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
)

type Config struct {
	Type  string
	Size  int
	Curve int
	Alg   string
	Use   string
}

func Generate(config Config) (jose.JSONWebKey, error) {
	var (
		jwk = jose.JSONWebKey{
			KeyID: uuid.New().String(),
		}
		err error
	)

	switch config.Use {
	case "sig":
		jwk.Use = "sig"

		switch config.Type {
		case "rsa":
			switch config.Alg {
			case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
				jwk.Algorithm = config.Alg
			case "":
				jwk.Algorithm = "RS256"
			default:
				return jwk, fmt.Errorf("unknown algorithm: %s (use RS256, RS384, RS512, PS256, PS384, PS512)", config.Alg)
			}

		case "ec":
			switch config.Alg {
			case "ES256", "ES384", "ES512":
				jwk.Algorithm = config.Alg
			case "":
				jwk.Algorithm = "ES256"
			default:
				return jwk, fmt.Errorf("unknown algorithm: %s (use ES256, ES384 or ES512)", config.Alg)
			}
		}

	case "enc":
		jwk.Use = "enc"

		switch config.Type {
		case "rsa":
			switch config.Alg {
			case "RSA1_5", "RSA-OAEP", "RSA-OAEP-256":
				jwk.Algorithm = config.Alg
			case "":
				jwk.Algorithm = "RSA-OAEP-256"
			default:
				return jwk, fmt.Errorf("unknown algorithm: %s (use RSA1_5, RSA-OAEP, RSA-OAEP-256)", config.Alg)
			}

		case "ec":
			switch config.Alg {
			case "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW":
				jwk.Algorithm = config.Alg
			case "":
				jwk.Algorithm = "ECDH-ES+A128KW"
			}
		}

	default:
		return jwk, fmt.Errorf("invalid use: %s (use sig or enc)", config.Use)
	}

	switch config.Type {
	case "rsa":
		var size int

		switch config.Size {
		case 2048, 3072, 4096:
			size = config.Size
		default:
			return jwk, fmt.Errorf("invalid key size: %d (use 2048, 3072 or 4096)", config.Size)
		}

		if jwk.Key, err = rsa.GenerateKey(rand.Reader, size); err != nil {
			return jwk, err
		}

	case "ec":
		var curve elliptic.Curve

		switch config.Curve {
		case 224:
			curve = elliptic.P224()
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return jwk, fmt.Errorf("unknown elliptic curve: %d (use 224, 256, 284 or 521)", config.Curve)
		}

		if jwk.Key, err = ecdsa.GenerateKey(curve, rand.Reader); err != nil {
			return jwk, err
		}

	default:
		return jwk, fmt.Errorf("uknown key type: %s (use rsa or ec)", config.Type)
	}

	return jwk, nil
}
