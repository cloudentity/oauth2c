package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/golang-jwt/jwt"
	"github.com/imdario/mergo"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
)

const (
	addr = "localhost:9876"
)

var (
	parser jwt.Parser
	silent bool
)

func OAuth2Cmd() *cobra.Command {
	var cconfig oauth2.ClientConfig

	cmd := &cobra.Command{
		Use:   "oauthc [issuer url or json config file]",
		Short: "User-friendly command-line for OAuth2",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
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
				browser.Stdout = ioutil.Discard
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

			if err := Authorize(cconfig, hc); err != nil {
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
		},
	}

	cmd.AddCommand(versionCmd)

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
	cmd.PersistentFlags().BoolVar(&cconfig.NoPKCE, "no-pkce", false, "disable proof key for code exchange (PKCE)")
	cmd.PersistentFlags().StringVar(&cconfig.Assertion, "assertion", "", "claims for jwt bearer assertion (standard claims such as iss, aud, iat, exp, jti are automatically generated)")
	cmd.PersistentFlags().StringVar(&cconfig.SigningKey, "signing-key", "", "path or url to signing key in jwks format")
	cmd.PersistentFlags().StringVar(&cconfig.SubjectToken, "subject-token", "", "third party access token")
	cmd.PersistentFlags().StringVar(&cconfig.SubjectTokenType, "subject-token-type", "", "third party access token type")
	cmd.PersistentFlags().StringVar(&cconfig.ActorToken, "actor-token", "", "acting party access token")
	cmd.PersistentFlags().StringVar(&cconfig.ActorTokenType, "actor-token-type", "", "acting party access token type")
	cmd.PersistentFlags().StringVar(&cconfig.TLSCert, "tls-cert", "", "path to tls cert pem file")
	cmd.PersistentFlags().StringVar(&cconfig.TLSKey, "tls-key", "", "path to tls key pem file")
	cmd.PersistentFlags().StringVar(&cconfig.TLSRootCA, "tls-root-ca", "", "path to tls root ca pem file")
	cmd.PersistentFlags().BoolVar(&cconfig.Insecure, "insecure", false, "allow insecure connections")
	cmd.PersistentFlags().BoolVarP(&silent, "silent", "s", false, "silent mode")

	return cmd
}

func Authorize(clientConfig oauth2.ClientConfig, hc *http.Client) error {
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
		return AuthorizationCodeGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.ImplicitGrantType:
		return ImplicitGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.ClientCredentialsGrantType:
		return ClientCredentialsGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.PasswordGrantType:
		return PasswordGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.RefreshTokenGrantType:
		return RefreshTokenGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.JWTBearerGrantType:
		return JWTBearerGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.TokenExchangeGrantType:
		return TokenExchangeGrantFlow(clientConfig, serverConfig, hc)
	}

	return fmt.Errorf("Unknown grant type: %s", clientConfig.GrantType)
}
