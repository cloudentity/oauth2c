package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/pkg/browser"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var clientConfig oauth2.ClientConfig

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

		if err := Authorize(); err != nil {
			var oauthErr *oauth2.Error

			if ok := errors.As(err, &oauthErr); ok {
				pterm.Error.PrintOnError(err)
				LogJson(oauthErr)
			} else {
				pterm.Error.PrintOnError(err)
			}

			os.Exit(1)
		}
	},
}

func Authorize() error {
	var (
		serverConfig oauth2.ServerConfig
		authorizeURL *url.URL
		addr         = "localhost:9876"
		output       map[string]interface{}
		code         string
		err          error
	)

	openidConfigurationStatus, _ := pterm.DefaultSpinner.Start("Fetching OpenID configuration")

	if serverConfig, err = oauth2.FetchOpenIDConfiguration(context.Background(), clientConfig.IssuerURL, http.DefaultClient); err != nil {
		return err
	}

	openidConfigurationStatus.Success("Fetched OpenID configuration")

	if authorizeURL, err = oauth2.BuildAuthorizeURL(addr, clientConfig, serverConfig); err != nil {
		return err
	}

	pterm.Info.Println("Open the following URL:")
	pterm.Println()
	pterm.Println(authorizeURL)
	pterm.Println()

	browser.OpenURL(authorizeURL.String())

	callbackStatus, _ := pterm.DefaultSpinner.Start("Waiting for callback")

	if code, err = oauth2.WaitForCallback(addr); err != nil {
		return err
	}

	callbackStatus.Success("Obtained authorization code")

	exchangeStatus, _ := pterm.DefaultSpinner.Start("Exchaging authorization code for access token")

	if output, err = oauth2.ExchangeCode(context.Background(), addr, code, clientConfig, serverConfig, http.DefaultClient); err != nil {
		return err
	}

	exchangeStatus.Success("Exchanged authorization code for access token")

	LogJson(output)

	return nil
}

func Execute() {
	if err := oauth2Cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
