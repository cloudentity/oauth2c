package oauth2

import (
	"crypto"
	"encoding/base64"
	"net/http"

	"github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"
	"github.com/pquerna/dpop"
	josev2 "gopkg.in/square/go-jose.v2"
)

func DPoPSignRequest(signingKey string, hc *http.Client, r *http.Request) error {
	var (
		key   jose.JSONWebKey
		proof dpop.Proof
		err   error
	)

	if key, err = loadKey(signingKey, hc); err != nil {
		return err
	}

	if proof, err = dpop.New(josev2.SigningKey{Algorithm: josev2.SignatureAlgorithm(key.Algorithm), Key: key.Key}); err != nil {
		return err
	}

	if err = proof.ForRequest(r, nil); err != nil {
		return err
	}

	return nil
}

func DPoPThumbprint(signingKey string, hc *http.Client) (string, error) {
	var (
		key        jose.JSONWebKey
		thumbprint []byte
		err        error
	)

	if key, err = loadKey(signingKey, hc); err != nil {
		return "", err
	}

	public := key.Public()

	if thumbprint, err = public.Thumbprint(crypto.SHA256); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func loadKey(signingKey string, hc *http.Client) (jose.JSONWebKey, error) {
	var (
		key jose.JSONWebKey
		err error
	)

	if signingKey == "" {
		return key, errors.New("no DPoP signing key path")
	}

	if key, err = ReadKey(SigningKey, signingKey, hc); err != nil {
		return key, errors.Wrapf(err, "failed to read signing key from %s", signingKey)
	}

	return key, nil
}
