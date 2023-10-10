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
	case "sig", "enc":
		jwk.Use = config.Use
	default:
		return jwk, fmt.Errorf("invalid use: %s (use sig or enc)", config.Use)
	}

	switch config.Type {
	case "rsa", "ps":
		if jwk.Key, err = rsa.GenerateKey(rand.Reader, config.Size); err != nil {
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
		return jwk, fmt.Errorf("uknown key type: %s (use rsa, ec or ps)", config.Type)
	}

	switch config.Type {

	case "rsa":
		jwk.Algorithm = "RS256"
	case "ps":
		jwk.Algorithm = "RS256"
	case "ec":
		jwk.Algorithm = "ES256"
	}

	return jwk, nil
}
