package oauth2

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

const (
	DPoPHeaderName = "DPoP"
	DPoPHeaderType = "dpop+jwt"
)

type DPoPClaims struct {
	Htm      string `json:"htm"`
	Htu      string `json:"htu"`
	Jti      string `json:"jti"`
	IssuedAt int64  `json:"iat"`
}

func DPoPSignRequest(signingKey string, hc *http.Client, r *http.Request) error {
	var (
		key       jose.JSONWebKey
		proof     string
		signer    jose.Signer
		bytes     []byte
		signature *jose.JSONWebSignature
		err       error
	)

	if key, err = ReadKey(SigningKey, signingKey, hc); err != nil {
		return errors.Wrapf(err, "failed to read signing key from %s", signingKey)
	}

	if key.Algorithm == "" {
		return errors.New("signing key algorithm must be set")
	}

	if key.IsPublic() {
		return errors.New("signing key must be private")
	}

	if !key.Valid() {
		return errors.New("signing key is not valid")
	}

	sig := jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(key.Algorithm),
		Key:       key.Key,
	}

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderType: DPoPHeaderType,
		},
		EmbedJWK: true,
	}

	if signer, err = jose.NewSigner(sig, opts); err != nil {
		return errors.Wrapf(err, "failed to create signer")
	}

	claims := DPoPClaims{
		Htm:      r.Method,
		Htu:      r.URL.String(),
		Jti:      uuid.New().String(),
		IssuedAt: time.Now().Unix(),
	}

	if bytes, err = json.Marshal(claims); err != nil {
		return err
	}

	if signature, err = signer.Sign(bytes); err != nil {
		return err
	}

	if proof, err = signature.CompactSerialize(); err != nil {
		return err
	}

	r.Header.Set(DPoPHeaderName, proof)

	return nil
}

func DPoPThumbprint(signingKey string, hc *http.Client) (string, error) {
	var (
		key        jose.JSONWebKey
		thumbprint []byte
		err        error
	)

	if key, err = ReadKey(SigningKey, signingKey, hc); err != nil {
		return "", errors.Wrapf(err, "failed to read signing key from %s", signingKey)
	}

	public := key.Public()

	if thumbprint, err = public.Thumbprint(crypto.SHA256); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}
