package oauth2_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/stretchr/testify/require"

	jose "github.com/go-jose/go-jose/v3"
)

func TestReadKey(t *testing.T) {
	key, err := oauth2.ReadKey("./testdata/jwks-private.json", http.DefaultClient)
	require.NoError(t, err)

	require.NotNil(t, key)
}

func TestSignJWT(t *testing.T) {
	key, err := oauth2.ReadKey("./testdata/jwks-private.json", http.DefaultClient)
	require.NoError(t, err)

	claims := oauth2.AssertionClaims(
		map[string]interface{}{
			"sub": "jdoe@example.com",
		},
		oauth2.ServerConfig{
			Issuer:        "https://example.com/tid/aid",
			TokenEndpoint: "https://example.com/tid/aid/oauth2/token",
		},
	)

	jwt, err := oauth2.SignJWT(claims, oauth2.JWKSigner(key))
	require.NoError(t, err)

	jws, err := jose.ParseSigned(jwt)
	require.NoError(t, err)

	bs, err := jws.Verify(key.Public())
	require.NoError(t, err)

	m := map[string]interface{}{}

	err = json.Unmarshal(bs, &m)
	require.NoError(t, err)

	require.Equal(t, "jdoe@example.com", m["sub"].(string))
	require.NotEmpty(t, m["aud"].(string))
	require.NotEmpty(t, m["iss"].(string))
	require.NotEmpty(t, m["jti"].(string))
}
