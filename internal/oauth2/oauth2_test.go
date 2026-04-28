package oauth2_test

import (
	"encoding/json"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/cloudentity/oauth2c/internal/oauth2"
)

func TestTokenResponseExtraFields(t *testing.T) {
	body := []byte(`{
		"access_token": "token",
		"expires_in": 3600,
		"token_type": "Bearer",
		"email": "me@email.com",
		"environment_id": "envid-token-here",
		"legal_entity_name": "oauth environment provider"
	}`)

	var resp oauth2.TokenResponse
	require.NoError(t, json.Unmarshal(body, &resp))

	require.Equal(t, "token", resp.AccessToken)
	require.Equal(t, oauth2.FlexibleInt64(3600), resp.ExpiresIn)
	require.Equal(t, "Bearer", resp.TokenType)

	out, err := json.Marshal(resp)
	require.NoError(t, err)

	var roundTrip map[string]any
	require.NoError(t, json.Unmarshal(out, &roundTrip))

	require.Equal(t, "token", roundTrip["access_token"])
	require.Equal(t, "Bearer", roundTrip["token_type"])
	require.Equal(t, "me@email.com", roundTrip["email"])
	require.Equal(t, "envid-token-here", roundTrip["environment_id"])
	require.Equal(t, "oauth environment provider", roundTrip["legal_entity_name"])
	require.NotContains(t, roundTrip, "raw")
}

func TestTokenResponseNoExtraFields(t *testing.T) {
	body := []byte(`{"access_token": "token", "expires_in": 3600, "token_type": "Bearer"}`)

	var resp oauth2.TokenResponse
	require.NoError(t, json.Unmarshal(body, &resp))

	out, err := json.Marshal(resp)
	require.NoError(t, err)

	var roundTrip map[string]any
	require.NoError(t, json.Unmarshal(out, &roundTrip))

	require.Equal(t, "token", roundTrip["access_token"])
	require.Equal(t, "Bearer", roundTrip["token_type"])
	require.Len(t, roundTrip, 3)
}

func TestTokenResponseTypedFieldsWinOnConflict(t *testing.T) {
	body := []byte(`{"access_token": "from-server", "expires_in": "3600"}`)

	var resp oauth2.TokenResponse
	require.NoError(t, json.Unmarshal(body, &resp))

	resp.AccessToken = "overridden"

	out, err := json.Marshal(resp)
	require.NoError(t, err)

	var roundTrip map[string]any
	require.NoError(t, json.Unmarshal(out, &roundTrip))

	require.Equal(t, "overridden", roundTrip["access_token"])
	require.EqualValues(t, 3600, roundTrip["expires_in"])
}

func TestUnmarshalExpires(t *testing.T) {
	tests := map[string]struct {
		bytes         []byte
		expectedValue oauth2.FlexibleInt64
		expectedErr   error
	}{
		"number": {
			bytes:         []byte(`{"expires_in": 3600}`),
			expectedValue: 3600,
			expectedErr:   nil,
		},
		"number string": {
			bytes:         []byte(`{"expires_in": "3600"}`),
			expectedValue: 3600,
			expectedErr:   nil,
		},
		"null": {
			bytes:         []byte(`{"expires_in": null}`),
			expectedValue: 0,
			expectedErr:   nil,
		},
		"other string": {
			bytes:         []byte(`{"expires_in": "foo"}`),
			expectedValue: 0,
			expectedErr:   errors.New("invalid syntax"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tokenResponse := oauth2.TokenResponse{}
			err := json.Unmarshal(test.bytes, &tokenResponse)
			if test.expectedErr != nil {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedErr.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expectedValue, tokenResponse.ExpiresIn)
			}
		})
	}
}
