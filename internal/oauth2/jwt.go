package oauth2

import "github.com/go-jose/go-jose/v3/jwt"

func UnsafeParseJWT(token string) (*jwt.JSONWebToken, map[string]interface{}, error) {
	var (
		t      *jwt.JSONWebToken
		claims = map[string]interface{}{}
		err    error
	)

	if t, err = jwt.ParseSigned(token); err != nil {
		return nil, nil, err
	}

	if err = t.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, nil, err
	}

	return t, claims, nil
}
