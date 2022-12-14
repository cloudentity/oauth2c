package oauth2

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"

	jose "github.com/go-jose/go-jose/v3"
)

type KeyUse string

const (
	SigningKey    KeyUse = "sig"
	EncryptionKey KeyUse = "enc"
)

func ReadKey(use KeyUse, location string, hc *http.Client) (jose.JSONWebKey, error) {
	var (
		keys jose.JSONWebKeySet
		bs   []byte
		resp *http.Response
		err  error
	)

	if strings.HasPrefix(location, "http") {
		if resp, err = hc.Get(location); err != nil {
			return jose.JSONWebKey{}, errors.Wrapf(err, "failed to call: %s", location)
		}
		defer resp.Body.Close()

		if bs, err = io.ReadAll(resp.Body); err != nil {
			return jose.JSONWebKey{}, errors.Wrapf(err, "failed to read response body from: %s", location)
		}

		if resp.StatusCode != 200 {
			return jose.JSONWebKey{}, fmt.Errorf("received unexpected status code: %d, body: %s", resp.StatusCode, string(bs))
		}
	} else {
		if bs, err = os.ReadFile(location); err != nil {
			return jose.JSONWebKey{}, errors.Wrapf(err, "failed to read file: %s", location)
		}
	}

	if err = json.Unmarshal(bs, &keys); err != nil {
		return jose.JSONWebKey{}, errors.Wrapf(err, "failed to parse jwks keys: %s", location)
	}

	if len(keys.Keys) == 0 {
		return jose.JSONWebKey{}, errors.New("keys are empty")
	}

	for _, key := range keys.Keys {
		if key.Use == string(use) {
			return key, nil
		}
	}

	return jose.JSONWebKey{}, fmt.Errorf("could not find %s key", use)
}

type SignerProvider func() (jose.Signer, interface{}, error)

func JWKSigner(clientConfig ClientConfig, hc *http.Client) SignerProvider {
	return func() (signer jose.Signer, _ interface{}, err error) {
		var key jose.JSONWebKey

		if clientConfig.SigningKey == "" {
			return nil, nil, errors.New("no signing key path")
		}

		if key, err = ReadKey(SigningKey, clientConfig.SigningKey, hc); err != nil {
			return nil, nil, errors.Wrapf(err, "failed to read signing key from %s", clientConfig.SigningKey)
		}

		if signer, err = jose.NewSigner(jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(key.Algorithm),
			Key:       key.Key,
		}, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{"kid": key.KeyID},
		}); err != nil {
			return nil, nil, errors.Wrapf(err, "failed to create a signer")
		}

		return signer, key.Key, nil
	}
}

func SecretSigner(secret []byte) SignerProvider {
	return func() (jose.Signer, interface{}, error) {
		signer, err := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.HS256,
			Key:       secret,
		}, nil)

		return signer, secret, err
	}
}

type ClaimsProvider func() (map[string]interface{}, error)

func AssertionClaims(serverConfig ServerConfig, clientConfig ClientConfig) ClaimsProvider {
	return func() (map[string]interface{}, error) {
		var err error

		claims := map[string]interface{}{
			"iss": serverConfig.TokenEndpoint,
			"aud": serverConfig.TokenEndpoint,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Minute * 10).Unix(),
			"jti": RandomString(20),
		}

		if clientConfig.Assertion == "" {
			clientConfig.Assertion = "{}"
		}

		if err = json.Unmarshal([]byte(clientConfig.Assertion), &claims); err != nil {
			return nil, err
		}

		return claims, nil
	}
}

func ClientAssertionClaims(serverConfig ServerConfig, clientConfig ClientConfig) ClaimsProvider {
	return func() (map[string]interface{}, error) {
		return map[string]interface{}{
			"iss": clientConfig.ClientID,
			"sub": clientConfig.ClientID,
			"aud": serverConfig.TokenEndpoint,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Minute * 10).Unix(),
			"jti": RandomString(20),
		}, nil
	}
}

func SignJWT(claimsProvider ClaimsProvider, signerProvider SignerProvider) (jwt string, key interface{}, err error) {
	var (
		signer jose.Signer
		claims map[string]interface{}
		jws    *jose.JSONWebSignature
		bs     []byte
	)

	if signer, key, err = signerProvider(); err != nil {
		return "", nil, errors.Wrapf(err, "failed to create signer")
	}

	if claims, err = claimsProvider(); err != nil {
		return "", nil, errors.Wrapf(err, "failed to build claims")
	}

	if bs, err = json.Marshal(claims); err != nil {
		return "", nil, errors.Wrapf(err, "failed to serialize claims")
	}

	if jws, err = signer.Sign(bs); err != nil {
		return "", nil, errors.Wrapf(err, "failed to sign jwt")
	}

	if jwt, err = jws.CompactSerialize(); err != nil {
		return "", nil, err
	}

	return jwt, key, nil
}
