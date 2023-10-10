package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/imdario/mergo"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
)

var (
	silent   bool
	noPrompt bool
)

var example = `oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
	--client-id cauktionbud6q8ftlqq0 \
	--client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
	--grant-type client_credentials \
	--auth-method client_secret_basic \
	--scopes introspect_tokens,revoke_tokens`

var desc = `oauth2c is a command-line tool for interacting with OAuth 2.0 authorization servers.

Its goal is to make it easy to fetch access tokens using any grant type or client authentication method.

It is compliant with almost all basic and advanced OAuth 2.0, OIDC, OIDF FAPI and JWT profiles.`

type OAuth2Cmd struct {
	*cobra.Command
}

func NewOAuth2Cmd() (cmd *OAuth2Cmd) {
	var cconfig oauth2.ClientConfig

	cmd = &OAuth2Cmd{
		Command: &cobra.Command{
			Use:     "oauth2c issuerURL",
			Short:   "User-friendly command-line for OAuth2",
			Example: example,
			Long:    desc,
			Args:    cobra.ExactArgs(1),
		},
	}

	cmd.Command.Run = cmd.Run(&cconfig)

	cmd.AddCommand(versionCmd)
	cmd.AddCommand(docsCmd)
	cmd.AddCommand(jwksCmd)

	cmd.Flags().StringVar(&cconfig.RedirectURL, "redirect-url", "http://localhost:9876/callback", "client redirect url")
	cmd.Flags().StringVar(&cconfig.ClientID, "client-id", "", "client identifier")
	cmd.Flags().StringVar(&cconfig.ClientSecret, "client-secret", "", "client secret")
	cmd.Flags().StringVar(&cconfig.GrantType, "grant-type", "", "grant type")
	cmd.Flags().StringVar(&cconfig.AuthMethod, "auth-method", "", "token endpoint authentication method")
	cmd.Flags().StringVar(&cconfig.Username, "username", "", "resource owner password credentials grant flow username")
	cmd.Flags().StringVar(&cconfig.Password, "password", "", "resource owner password credentials grant flow password")
	cmd.Flags().StringVar(&cconfig.RefreshToken, "refresh-token", "", "refresh token")
	cmd.Flags().StringSliceVar(&cconfig.ResponseType, "response-types", []string{""}, "response type")
	cmd.Flags().StringVar(&cconfig.ResponseMode, "response-mode", "", "response mode")
	cmd.Flags().StringSliceVar(&cconfig.Scopes, "scopes", []string{}, "requested scopes")
	cmd.Flags().StringSliceVar(&cconfig.Audience, "audience", []string{}, "requested audience")
	cmd.Flags().BoolVar(&cconfig.PKCE, "pkce", false, "enable proof key for code exchange (PKCE)")
	cmd.Flags().BoolVar(&cconfig.PAR, "par", false, "enable pushed authorization requests (PAR)")
	cmd.Flags().BoolVar(&cconfig.RequestObject, "request-object", false, "pass request parameters as jwt")
	cmd.Flags().BoolVar(&cconfig.EncryptedRequestObject, "encrypted-request-object", false, "pass request parameters as encrypted jwt")
	cmd.Flags().StringVar(&cconfig.Assertion, "assertion", "", "claims for jwt bearer assertion")
	cmd.Flags().StringVar(&cconfig.SigningKey, "signing-key", "", "path or url to signing key in jwks format")
	cmd.Flags().StringVar(&cconfig.EncryptionKey, "encryption-key", "", "path or url to encryption key in jwks format")
	cmd.Flags().StringVar(&cconfig.SubjectToken, "subject-token", "", "third party token")
	cmd.Flags().StringVar(&cconfig.SubjectTokenType, "subject-token-type", "", "third party token type")
	cmd.Flags().StringVar(&cconfig.ActorToken, "actor-token", "", "acting party token")
	cmd.Flags().StringVar(&cconfig.ActorTokenType, "actor-token-type", "", "acting party token type")
	cmd.Flags().StringVar(&cconfig.IDTokenHint, "id-token-hint", "", "id token hint")
	cmd.Flags().StringVar(&cconfig.LoginHint, "login-hint", "", "user identifier hint")
	cmd.Flags().StringVar(&cconfig.IDPHint, "idp-hint", "", "identity provider hint")
	cmd.Flags().StringVar(&cconfig.TLSCert, "tls-cert", "", "path to tls cert pem file")
	cmd.Flags().StringVar(&cconfig.TLSKey, "tls-key", "", "path to tls key pem file")
	cmd.Flags().StringVar(&cconfig.TLSRootCA, "tls-root-ca", "", "path to tls root ca pem file")
	cmd.Flags().DurationVar(&cconfig.HTTPTimeout, "http-timeout", time.Minute, "http client timeout")
	cmd.Flags().DurationVar(&cconfig.BrowserTimeout, "browser-timeout", 10*time.Minute, "browser timeout")
	cmd.Flags().BoolVar(&cconfig.Insecure, "insecure", false, "allow insecure connections")
	cmd.Flags().BoolVarP(&silent, "silent", "s", false, "silent mode")
	cmd.Flags().BoolVar(&noPrompt, "no-prompt", false, "disable prompt")
	cmd.Flags().BoolVar(&cconfig.DPoP, "dpop", false, "use DPoP")
	cmd.Flags().StringVar(&cconfig.Claims, "claims", "", "use claims")
	cmd.Flags().StringVar(&cconfig.RAR, "rar", "", "use rich authorization request (RAR)")
	cmd.Flags().StringSliceVar(&cconfig.ACRValues, "acr-values", []string{}, "ACR values")

	return cmd
}

func (c *OAuth2Cmd) Run(cconfig *oauth2.ClientConfig) func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		var (
			config Config
			data   []byte
			cert   tls.Certificate
			err    error
		)

		if data, err = os.ReadFile(args[0]); err == nil {
			if err = json.Unmarshal(data, &config); err != nil {
				LogError(err)
				os.Exit(1)
			}

			if err := mergo.Merge(&cconfig, config.ToClientConfig()); err != nil {
				LogError(err)
				os.Exit(1)
			}
		} else {
			cconfig.IssuerURL = strings.TrimSuffix(args[0], oauth2.OpenIDConfigurationPath)
		}

		if silent {
			browser.Stdout = io.Discard
		} else {
			browser.Stdout = os.Stderr
		}

		tr := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cconfig.Insecure,
				MinVersion:         tls.VersionTLS12,
			},
		}

		hc := &http.Client{Timeout: cconfig.HTTPTimeout, Transport: tr}

		if cconfig.TLSCert != "" && cconfig.TLSKey != "" {
			if cert, err = oauth2.ReadKeyPair(cconfig.TLSCert, cconfig.TLSKey, hc); err != nil {
				LogError(err)
				os.Exit(1)
			}

			tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
		}

		if cconfig.TLSRootCA != "" {
			if tr.TLSClientConfig.RootCAs, err = oauth2.ReadRootCA(cconfig.TLSRootCA, hc); err != nil {
				LogError(err)
				os.Exit(1)
			}
		}

		if err := c.Authorize(*cconfig, hc); err != nil {
			var oauth2Error *oauth2.Error

			if errors.As(err, &oauth2Error) {
				switch oauth2Error.Hint {
				case "Clients must include a code_challenge when performing the authorize code flow, but it is missing.":
					LogWarning("Authorization server enforces PKCE. Use --pkce flag.")
				}
			}

			LogError(err)
			os.Exit(1)
		}
	}
}

func (c *OAuth2Cmd) Authorize(clientConfig oauth2.ClientConfig, hc *http.Client) error {
	var (
		serverRequest oauth2.Request
		serverConfig  oauth2.ServerConfig
		err           error
	)

	// openid configuration
	if serverRequest, serverConfig, err = oauth2.FetchOpenIDConfiguration(
		context.Background(),
		clientConfig.IssuerURL,
		hc,
	); err != nil {
		LogRequestln(serverRequest)
		return err
	}

	if !silent && !noPrompt {
		clientConfig = PromptForClientConfig(clientConfig, serverConfig)
	}

	LogInputData(clientConfig)

	switch clientConfig.GrantType {
	case oauth2.AuthorizationCodeGrantType:
		return c.AuthorizationCodeGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.ImplicitGrantType:
		return c.ImplicitGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.ClientCredentialsGrantType:
		return c.ClientCredentialsGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.PasswordGrantType:
		return c.PasswordGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.RefreshTokenGrantType:
		return c.RefreshTokenGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.JWTBearerGrantType:
		return c.JWTBearerGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.TokenExchangeGrantType:
		return c.TokenExchangeGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.DeviceGrantType:
		return c.DeviceGrantFlow(clientConfig, serverConfig, hc)
	}

	return fmt.Errorf("Unknown grant type: %s", clientConfig.GrantType)
}

func (c *OAuth2Cmd) PrintResult(result interface{}) {
	output, err := json.Marshal(result)

	if err != nil {
		fmt.Fprintf(c.ErrOrStderr(), "%+v", err)
		fmt.Fprintln(c.ErrOrStderr())
		return
	}

	fmt.Fprintln(c.OutOrStdout(), string(output))
}
