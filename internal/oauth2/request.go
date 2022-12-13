package oauth2

import (
	"crypto/x509"
	"net/url"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
)

type Request struct {
	Method  string
	URL     *url.URL
	Headers map[string][]string
	Form    url.Values
	JARM    map[string]interface{}
	Key     interface{}
	Cert    *x509.Certificate
}

func (r *Request) Get(key string) string {
	if v, ok := r.JARM[key].(string); ok {
		return v
	}

	if v := r.URL.Query().Get(key); v != "" {
		return v
	}

	return r.Form.Get(key)
}

func (r *Request) ParseJARM(key interface{}) error {
	var (
		response    = r.Get("response")
		token       *jwt.JSONWebToken
		nestedToken *jwt.NestedJSONWebToken
		err         error
		err2        error
	)

	r.JARM = map[string]interface{}{}

	if response != "" {
		if nestedToken, err = jwt.ParseSignedAndEncrypted(response); err != nil {
			if token, err2 = jwt.ParseSigned(response); err2 != nil {
				return errors.Wrapf(multierror.Append(err, err2), "failed to parse JARM response")
			}
		} else if token, err = nestedToken.Decrypt(key); err != nil {
			return errors.Wrapf(err, "failed to decrypt encrypted JARM response")
		}

		if err = token.UnsafeClaimsWithoutVerification(&r.JARM); err != nil {
			return err
		}
	}

	return nil
}
