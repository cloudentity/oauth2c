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
	clientConfig oauth2.ClientConfig
	parser       jwt.Parser
)

func init() {
	oauth2Cmd.PersistentFlags().StringVar(&clientConfig.ClientID, "client-id", "", "client identifier")
	oauth2Cmd.PersistentFlags().StringVar(&clientConfig.ClientSecret, "client-secret", "", "client secret")
	oauth2Cmd.MarkPersistentFlagRequired("client-id")
}

var oauth2Cmd = &cobra.Command{
	Use:   "oauthc [issuer-url]",
	Short: "Obtain authorization from the resource owner",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		clientConfig.IssuerURL = args[0]

		_ = pterm.DefaultBigText.WithLetters(putils.LettersFromString("OAuth2c")).Render()

		if err := Authorize(); err != nil {
			pterm.Error.PrintOnError(err)
			os.Exit(1)
		}
	},
}

func Authorize() error {
	var (
		serverRequest    oauth2.Request
		serverConfig     oauth2.ServerConfig
		authorizeRequest oauth2.Request
		addr             = "localhost:9876"
		callbackRequest  oauth2.Request
		tokenRequest     oauth2.Request
		tokenResponse    oauth2.TokenResponse
		atClaims         jwt.MapClaims
		idClaims         jwt.MapClaims
		err              error
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

	pterm.DefaultHeader.WithFullWidth().Println("Authorization Code Flow")

	// authorize endpoint
	pterm.DefaultSection.Println("Request authorization")

	if authorizeRequest, err = oauth2.BuildAuthorizeRequest(addr, clientConfig, serverConfig); err != nil {
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

	if tokenRequest, tokenResponse, err = oauth2.ExchangeCode(
		context.Background(),
		addr,
		callbackRequest.URL.Query().Get("code"),
		clientConfig,
		serverConfig,
		http.DefaultClient,
	); err != nil {
		LogRequestAndResponseln(tokenRequest, err)
		return err
	}

	LogRequestAndResponse(tokenRequest, tokenResponse)

	// payload
	if tokenResponse.AccessToken != "" {
		if _, _, err = parser.ParseUnverified(tokenResponse.AccessToken, &atClaims); err != nil {
			return err
		}

		pterm.Println(pterm.FgGray.Sprint("Access token:"))
		LogJson(atClaims)
	}

	if tokenResponse.IDToken != "" {
		if _, _, err = parser.ParseUnverified(tokenResponse.IDToken, &idClaims); err != nil {
			return err
		}

		pterm.Println(pterm.FgGray.Sprint("ID token:"))
		LogJson(idClaims)
	}

	pterm.Println()

	exchangeStatus.Success("Exchanged authorization code for access token")

	return nil
}

func Execute() {
	if err := oauth2Cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
