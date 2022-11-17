package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	IssuerURL = "https://oauth2c.us.authz.cloudentity.io/oauth2c/demo"

	ClientCredentialsScopes = "introspect_tokens,revoke_tokens"

	TLSCertURL    = "https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/cert.pem"
	TLSKeyURL     = "https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/key.pem"
	SigningKeyURL = "https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/key.json"
)

type CommandTestCase struct {
	title string
	args  []string
	err   error
}

func (tc *CommandTestCase) Test() func(*testing.T) {
	return func(t *testing.T) {
		cmd := OAuth2Cmd()
		cmd.SetArgs(tc.args)
		err := cmd.Execute()

		if tc.err == nil {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			require.Equal(t, err.Error(), tc.err.Error())
		}
	}
}
