package oauth2_test

import (
	"encoding/json"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/cloudentity/oauth2c/internal/oauth2"
)

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
