package oauth2

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"
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
