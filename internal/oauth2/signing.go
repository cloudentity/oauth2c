package oauth2

import (
	"encoding/json"
	"io/ioutil"
	"time"

	"github.com/pkg/errors"

	jose "github.com/go-jose/go-jose/v3"
)

func ReadKey(file string) (jose.JSONWebKey, error) {
	var (
		keys jose.JSONWebKeySet
		bs   []byte
		err  error
	)

	if bs, err = ioutil.ReadFile(file); err != nil {
		return jose.JSONWebKey{}, errors.Wrapf(err, "failed to read file: %s", file)
	}

	if err = json.Unmarshal(bs, &keys); err != nil {
		return jose.JSONWebKey{}, errors.Wrapf(err, "failed to parse jwks keys: %s", file)
	}

	if len(keys.Keys) == 0 {
		return jose.JSONWebKey{}, errors.New("keys are empty")
	}

	return keys.Keys[0], nil
}

func SignJWT(claims map[string]interface{}, key jose.JSONWebKey) (string, error) {
	var (
		signer jose.Signer
		jws    *jose.JSONWebSignature
		bs     []byte
		err    error
	)

	if signer, err = jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(key.Algorithm),
		Key:       key.Key,
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{"kid": key.KeyID},
	}); err != nil {
		return "", errors.Wrapf(err, "failed to create signer")
	}

	if bs, err = json.Marshal(claims); err != nil {
		return "", errors.Wrapf(err, "failed to serialize claims")
	}

	if jws, err = signer.Sign(bs); err != nil {
		return "", errors.Wrapf(err, "failed to sign jwt")
	}

	return jws.CompactSerialize()
}

func WithStandardClaims(extra map[string]interface{}, serverConfig ServerConfig) map[string]interface{} {
	claims := map[string]interface{}{
		"iss": serverConfig.TokenEndpoint,
		"aud": serverConfig.TokenEndpoint,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute * 10).Unix(),
		"jti": RandomString(20),
	}

	for k, v := range extra {
		claims[k] = v
	}

	return claims
}
