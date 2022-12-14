package oauth2

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"
)

func TestSignJWT(t *testing.T) {
	key, err := ReadKey(SigningKey, "../../data/key.json", http.DefaultClient)
	require.NoError(t, err)

	claims := AssertionClaims(
		ServerConfig{
			Issuer:        "https://example.com/tid/aid",
			TokenEndpoint: "https://example.com/tid/aid/oauth2/token",
		},
		ClientConfig{
			Assertion: `{"sub": "jdoe@example.com"}`,
		},
	)

	jwt, _, err := SignJWT(claims, JWKSigner(ClientConfig{
		SigningKey: "../../data/key.json",
	}, http.DefaultClient))
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
