package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/browser"
	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"
	"github.com/spf13/cobra"
)

var (
	cconfig oauth2.ClientConfig
	addr    = "localhost:9876"
	parser  jwt.Parser
)

func init() {
	OAuth2Cmd.PersistentFlags().StringVar(&cconfig.ClientID, "client-id", "", "client identifier")
	OAuth2Cmd.PersistentFlags().StringVar(&cconfig.ClientSecret, "client-secret", "", "client secret")
	OAuth2Cmd.PersistentFlags().StringVar(&cconfig.GrantType, "grant-type", "", "grant type")
	OAuth2Cmd.PersistentFlags().StringVar(&cconfig.AuthMethod, "auth-method", "", "token endpoint authentication method")
}

var OAuth2Cmd = &cobra.Command{
	Use:   "oauthc [issuer-url]",
	Short: "Obtain authorization from the resource owner",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cconfig.IssuerURL = args[0]

		_ = pterm.DefaultBigText.WithLetters(putils.LettersFromString("OAuth2c")).Render()

		if err := Authorize(cconfig); err != nil {
			pterm.Error.PrintOnError(err)
			os.Exit(1)
		}
	},
}

func Authorize(clientConfig oauth2.ClientConfig) error {
	var (
		serverRequest oauth2.Request
		serverConfig  oauth2.ServerConfig
		err           error
	)

	// openid configuration
	if serverRequest, serverConfig, err = oauth2.FetchOpenIDConfiguration(
		context.Background(),
		clientConfig.IssuerURL,
		http.DefaultClient,
	); err != nil {
		LogRequestAndResponseln(serverRequest, err)
		return err
	}

	switch clientConfig.GrantType {
	case oauth2.AuthorizationCodeGrantType:
		return AuthorizationCodeGrantFlow(clientConfig, serverConfig)
	case oauth2.ClientCredentialsGrantType:
		return ClientCredentialsGrantFlow(clientConfig, serverConfig)
	}

	return fmt.Errorf("Unknown grant type: %s", clientConfig.GrantType)
}

func ClientCredentialsGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig) error {
	var (
		tokenRequest  oauth2.Request
		tokenResponse oauth2.TokenResponse
		err           error
	)

	pterm.DefaultHeader.WithFullWidth().Println("Client Credentials Flow")

	// request token
	pterm.DefaultSection.Println("Request authorization")

	tokenStatus, _ := pterm.DefaultSpinner.Start("Requesting authorization")

	if tokenRequest, tokenResponse, err = oauth2.RequestToken(
		context.Background(),
		clientConfig,
		serverConfig,
		http.DefaultClient,
	); err != nil {
		LogRequestAndResponseln(tokenRequest, err)
		return err
	}

	LogRequestAndResponse(tokenRequest, tokenResponse)
	LogTokenPayloadln(tokenResponse)

	tokenStatus.Success("Authorization completed")

	return nil
}

func AuthorizationCodeGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig) error {
	var (
		authorizeRequest oauth2.Request
		callbackRequest  oauth2.Request
		tokenRequest     oauth2.Request
		tokenResponse    oauth2.TokenResponse
		err              error
	)

	pterm.DefaultHeader.WithFullWidth().Println("Authorization Code Flow")

	// authorize endpoint
	pterm.DefaultSection.Println("Request authorization")

	if authorizeRequest, err = oauth2.RequestAuthorization(addr, clientConfig, serverConfig); err != nil {
		return err
	}

	LogRequest(authorizeRequest)

	pterm.Printfln("\nOpen the following URL:\n\n%s\n", authorizeRequest.URL.String())
	browser.OpenURL(authorizeRequest.URL.String())
	pterm.Println()

	// callback
	callbackStatus, _ := pterm.DefaultSpinner.Start("Waiting for callback")

	if callbackRequest, err = oauth2.WaitForCallback(addr); err != nil {
		LogRequestln(callbackRequest)
		return err
	}

	LogRequest(callbackRequest)
	pterm.Println()

	callbackStatus.Success("Obtained authorization code")

	pterm.DefaultSection.Println("Exchange authorization code for token")

	// token exchange
	exchangeStatus, _ := pterm.DefaultSpinner.Start("Exchaging authorization code for access token")

	if tokenRequest, tokenResponse, err = oauth2.RequestToken(
		context.Background(),
		clientConfig,
		serverConfig,
		http.DefaultClient,
		oauth2.WithAuthorizationCode(callbackRequest.URL.Query().Get("code")),
		oauth2.WithRedirectURL("http://"+addr+"/callback"),
	); err != nil {
		LogRequestAndResponseln(tokenRequest, err)
		return err
	}

	LogRequestAndResponse(tokenRequest, tokenResponse)
	LogTokenPayloadln(tokenResponse)

	exchangeStatus.Success("Exchanged authorization code for access token")

	return nil
}
