package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/sirupsen/logrus"
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
		var (
			serverConfig oauth2.ServerConfig
			authorizeURL *url.URL
			addr         = "localhost:9876"
			output       map[string]interface{}
			code         string
			err          error
		)

		clientConfig.IssuerURL = args[0]

		if serverConfig, err = oauth2.FetchOpenIDConfiguration(context.Background(), clientConfig.IssuerURL, http.DefaultClient); err != nil {
			logrus.WithError(err).Fatalf("failed to fetch openid configuration")
		}

		if authorizeURL, err = oauth2.BuildAuthorizeURL(addr, clientConfig, serverConfig); err != nil {
			logrus.WithError(err).Fatalf("failed to fetch openid configuration")
		}

		fmt.Printf("Go to %s\n", authorizeURL.String())

		if code, err = oauth2.WaitForCallback(addr); err != nil {
			logrus.WithError(err).Fatalf("failed to fetch authorization code")
		}

		logrus.Infof("Code: %s", code)

		if output, err = oauth2.ExchangeCode(context.Background(), addr, code, clientConfig, serverConfig, http.DefaultClient); err != nil {
			logrus.WithError(err).Fatalf("failed to exchange code for token")
		}

		logrus.WithField("output", output).Infof("Response")
	},
}

func Execute() {
	if err := oauth2Cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
