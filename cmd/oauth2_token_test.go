package cmd

import (
	"testing"

	"github.com/maordavidov/oauth2c/pkg/oauth2"
)

func TestOAuth2NonBrowserGrantTypes(t *testing.T) {
	testcases := []CommandTestCase{
		{
			title: "resource_owner",
			args: []string{
				IssuerURL,
				"--client-id", "cauktionbud6q8ftlqq0",
				"--client-secret", "HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc",
				"--grant-type", oauth2.PasswordGrantType,
				"--auth-method", oauth2.ClientSecretBasicAuthMethod,
				"--username", "demo",
				"--password", "demo",
				"--scopes", "openid",
			},
		},
		{
			title: "jwt_bearer",
			args: []string{
				IssuerURL,
				"--client-id", "cauktionbud6q8ftlqq0",
				"--client-secret", "HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc",
				"--grant-type", oauth2.JWTBearerGrantType,
				"--auth-method", oauth2.ClientSecretBasicAuthMethod,
				"--scopes", "email",
				"--signing-key", SigningKeyURL,
				"--assertion", `{"sub":"jdoe@example.com"}`,
			},
		},
		{
			title: "refresh_token",
			args: []string{
				IssuerURL,
				"--client-id", "cauktionbud6q8ftlqq0",
				"--client-secret", "HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc",
				"--grant-type", oauth2.RefreshTokenGrantType,
				"--auth-method", oauth2.ClientSecretBasicAuthMethod,
				"--refresh-token", "$REFRESH_TOKEN",
			},
			deps: map[string]CommandDependency{
				"REFRESH_TOKEN": {
					args: []string{
						IssuerURL,
						"--client-id", "cauktionbud6q8ftlqq0",
						"--client-secret", "HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc",
						"--grant-type", oauth2.PasswordGrantType,
						"--auth-method", oauth2.ClientSecretBasicAuthMethod,
						"--username", "demo", "--password", "demo",
						"--scopes", "offline_access",
						"--silent",
					},
					jq: ".refresh_token",
				},
			},
		},
		{
			title: "token_exchange",
			args: []string{
				IssuerURL,
				"--client-id", "cauktionbud6q8ftlqq0",
				"--client-secret", "HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc",
				"--grant-type", oauth2.TokenExchangeGrantType,
				"--auth-method", oauth2.ClientSecretBasicAuthMethod,
				"--scopes", "email",
				"--subject-token", "$SUBJECT_TOKEN",
				"--subject-token-type", "urn:ietf:params:oauth:token-type:access_token",
				"--actor-token", "$ACTOR_TOKEN",
				"--actor-token-type", "urn:ietf:params:oauth:token-type:access_token",
			},
			deps: map[string]CommandDependency{
				"SUBJECT_TOKEN": {
					args: []string{
						IssuerURL,
						"--client-id", "cauktionbud6q8ftlqq0",
						"--client-secret", "HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc",
						"--grant-type", oauth2.PasswordGrantType,
						"--auth-method", oauth2.ClientSecretBasicAuthMethod,
						"--username", "demo", "--password", "demo",
						"--silent",
					},
					jq: ".access_token",
				},
				"ACTOR_TOKEN": {
					args: []string{
						IssuerURL,
						"--client-id", "cauktionbud6q8ftlqq0",
						"--client-secret", "HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc",
						"--grant-type", oauth2.ClientCredentialsGrantType,
						"--auth-method", oauth2.ClientSecretBasicAuthMethod,
						"--scopes", ClientCredentialsScopes,
						"--silent",
					},
					jq: ".access_token",
				},
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.title, tc.Test())
	}
}

func TestOAuth2ClientAuthenticationMethods(t *testing.T) {
	testcases := []CommandTestCase{
		{
			title: "client_secret_basic",
			args: []string{
				IssuerURL,
				"--client-id", "cauktionbud6q8ftlqq0",
				"--client-secret", "HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc",
				"--grant-type", oauth2.ClientCredentialsGrantType,
				"--auth-method", oauth2.ClientSecretBasicAuthMethod,
				"--scopes", ClientCredentialsScopes,
			},
		},
		{
			title: "client_secret_post",
			args: []string{
				IssuerURL,
				"--client-id", "cauosoo2omc4fr8ai1fg",
				"--client-secret", "ipFkA1lMomOMI_d2HcGGQ7j8oxeHFqKw3kli76g92VM",
				"--grant-type", oauth2.ClientCredentialsGrantType,
				"--auth-method", oauth2.ClientSecretPostAuthMethod,
				"--scopes", ClientCredentialsScopes,
			},
		},
		{
			title: "client_secret_jwt",
			args: []string{
				IssuerURL,
				"--client-id", "ab966ce4f2ac4f4aa641582b099c32d3",
				"--client-secret", "578-WfFYfBheWb8gJpHYXMRRqR5HN0qv7d7xIolJnIE",
				"--grant-type", oauth2.ClientCredentialsGrantType,
				"--auth-method", oauth2.ClientSecretJwtAuthMethod,
				"--scopes", ClientCredentialsScopes,
			},
		},
		{
			title: "private_key_jwt",
			args: []string{
				IssuerURL,
				"--client-id", "582af0afb0d74554aa7af47849edb222",
				"--signing-key", SigningKeyURL,
				"--grant-type", oauth2.ClientCredentialsGrantType,
				"--auth-method", oauth2.PrivateKeyJwtAuthMethod,
				"--scopes", ClientCredentialsScopes,
			},
		},
		{
			title: "tls_client_auth",
			args: []string{
				IssuerURL,
				"--client-id", "3f07a8c2adea4c1ab353f3ca8e16b8fd",
				"--tls-cert", TLSCertURL,
				"--tls-key", TLSKeyURL,
				"--grant-type", oauth2.ClientCredentialsGrantType,
				"--auth-method", oauth2.TLSClientAuthMethod,
				"--scopes", ClientCredentialsScopes,
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.title, tc.Test())
	}
}
