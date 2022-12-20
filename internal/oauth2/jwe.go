package oauth2

import (
	"net/http"

	"github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"
)

type EncrypterProvider func() (jose.Encrypter, interface{}, error)

func JWEEncrypter(clientConfig ClientConfig, hc *http.Client) EncrypterProvider {
	return func() (encrypter jose.Encrypter, _ interface{}, err error) {
		var key jose.JSONWebKey

		if clientConfig.EncryptionKey == "" {
			return nil, nil, errors.New("no encryption key path")
		}

		if key, err = ReadKey(EncryptionKey, clientConfig.EncryptionKey, hc); err != nil {
			return nil, nil, errors.Wrapf(err, "failed to read encryption key from %s", clientConfig.EncryptionKey)
		}

		if encrypter, err = jose.NewEncrypter(
			jose.A256GCM,
			jose.Recipient{
				Algorithm: jose.KeyAlgorithm(key.Algorithm),
				Key:       key.Key,
			},
			(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"),
		); err != nil {
			return nil, nil, errors.Wrapf(err, "failed to create an encrypter")
		}

		return encrypter, key.Key, nil
	}
}

func EncryptJWT(token string, encrypterProvider EncrypterProvider) (nestedJWT string, key interface{}, err error) {
	var (
		encrypter jose.Encrypter
		jwe       *jose.JSONWebEncryption
	)

	if encrypter, key, err = encrypterProvider(); err != nil {
		return "", nil, err
	}

	if jwe, err = encrypter.Encrypt([]byte(token)); err != nil {
		return "", nil, err
	}

	if nestedJWT, err = jwe.CompactSerialize(); err != nil {
		return "", nil, err
	}

	return nestedJWT, key, nil
}
