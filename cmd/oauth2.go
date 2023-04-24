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
	silent bool
)

type OAuth2Cmd struct {
	*cobra.Command
}

func NewOAuth2Cmd() (cmd *OAuth2Cmd) {
	var cconfig oauth2.ClientConfig

	cmd = &OAuth2Cmd{
		Command: &cobra.Command{
			Use:   "oauthc [issuer url]",
			Short: "User-friendly command-line for OAuth2",
			Args:  cobra.ExactArgs(1),
		},
	}

	cmd.Command.Run = cmd.Run(&cconfig)

	cmd.AddCommand(versionCmd)

	cmd.PersistentFlags().StringVar(&cconfig.RedirectURL, "redirect-url", "http://localhost:9876/callback", "client redirect url")
	cmd.PersistentFlags().StringVar(&cconfig.ClientID, "client-id", "", "client identifier")
	cmd.PersistentFlags().StringVar(&cconfig.ClientSecret, "client-secret", "", "client secret")
	cmd.PersistentFlags().StringVar(&cconfig.GrantType, "grant-type", "", "grant type")
	cmd.PersistentFlags().StringVar(&cconfig.AuthMethod, "auth-method", "", "token endpoint authentication method")
	cmd.PersistentFlags().StringVar(&cconfig.Username, "username", "", "resource owner password credentials grant flow username")
	cmd.PersistentFlags().StringVar(&cconfig.Password, "password", "", "resource owner password credentials grant flow password")
	cmd.PersistentFlags().StringVar(&cconfig.RefreshToken, "refresh-token", "", "refresh token")
	cmd.PersistentFlags().StringSliceVar(&cconfig.ResponseType, "response-types", []string{""}, "response type")
	cmd.PersistentFlags().StringVar(&cconfig.ResponseMode, "response-mode", "", "response mode")
	cmd.PersistentFlags().StringSliceVar(&cconfig.Scopes, "scopes", []string{}, "requested scopes")
	cmd.PersistentFlags().BoolVar(&cconfig.PKCE, "pkce", false, "enable proof key for code exchange (PKCE)")
	cmd.PersistentFlags().BoolVar(&cconfig.PAR, "par", false, "enable pushed authorization requests (PAR)")
	cmd.PersistentFlags().BoolVar(&cconfig.RequestObject, "request-object", false, "pass request parameters as jwt")
	cmd.PersistentFlags().BoolVar(&cconfig.EncryptedRequestObject, "encrypted-request-object", false, "pass request parameters as encrypted jwt")
	cmd.PersistentFlags().StringVar(&cconfig.Assertion, "assertion", "", "claims for jwt bearer assertion")
	cmd.PersistentFlags().StringVar(&cconfig.SigningKey, "signing-key", "", "path or url to signing key in jwks format")
	cmd.PersistentFlags().StringVar(&cconfig.EncryptionKey, "encryption-key", "", "path or url to encryption key in jwks format")
	cmd.PersistentFlags().StringVar(&cconfig.SubjectToken, "subject-token", "", "third party token")
	cmd.PersistentFlags().StringVar(&cconfig.SubjectTokenType, "subject-token-type", "", "third party token type")
	cmd.PersistentFlags().StringVar(&cconfig.ActorToken, "actor-token", "", "acting party token")
	cmd.PersistentFlags().StringVar(&cconfig.ActorTokenType, "actor-token-type", "", "acting party token type")
	cmd.PersistentFlags().StringVar(&cconfig.IDTokenHint, "id-token-hint", "", "id token hint")
	cmd.PersistentFlags().StringVar(&cconfig.LoginHint, "login-hint", "", "user identifier hint")
	cmd.PersistentFlags().StringVar(&cconfig.IDPHint, "idp-hint", "", "identity provider hint")
	cmd.PersistentFlags().StringVar(&cconfig.TLSCert, "tls-cert", "", "path to tls cert pem file")
	cmd.PersistentFlags().StringVar(&cconfig.TLSKey, "tls-key", "", "path to tls key pem file")
	cmd.PersistentFlags().StringVar(&cconfig.TLSRootCA, "tls-root-ca", "", "path to tls root ca pem file")
	cmd.PersistentFlags().BoolVar(&cconfig.Insecure, "insecure", false, "allow insecure connections")
	cmd.PersistentFlags().BoolVarP(&silent, "silent", "s", false, "silent mode")
	cmd.PersistentFlags().BoolVar(&cconfig.DPoP, "dpop", false, "use DPoP")

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
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cconfig.Insecure,
				MinVersion:         tls.VersionTLS12,
			},
		}

		hc := &http.Client{Timeout: 10 * time.Second, Transport: tr}

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

	if !silent {
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
	if !silent {
		return
	}

	output, err := json.Marshal(result)

	if err != nil {
		fmt.Fprintf(c.ErrOrStderr(), "%+v", err)
		fmt.Fprintln(c.ErrOrStderr())
		return
	}

	fmt.Fprintln(c.OutOrStdout(), string(output))
}
