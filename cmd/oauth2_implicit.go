package cmd

import (
	"net/http"

	"github.com/cli/browser"
	"github.com/maordavidov/oauth2c/pkg/oauth2"
)

func (c *OAuth2Cmd) ImplicitGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	var (
		authorizeRequest oauth2.Request
		callbackRequest  oauth2.Request
		err              error
	)

	LogHeader("Implicit Flow")

	// authorize endpoint
	LogSection("Request authorization")

	if authorizeRequest, _, err = oauth2.RequestAuthorization(clientConfig, serverConfig, hc); err != nil {
		return err
	}

	LogRequest(authorizeRequest)

	Logfln("\nOpen the following URL:\n\n%s\n", authorizeRequest.URL.String())

	if err = browser.OpenURL(authorizeRequest.URL.String()); err != nil {
		LogError(err)
	}

	Logln()

	// callback
	callbackStatus := LogAction("Waiting for callback. Go to the browser to authenticate...")

	if callbackRequest, err = oauth2.WaitForCallback(clientConfig, serverConfig, hc); err != nil {
		LogRequestln(callbackRequest)
		return err
	}

	tokenResponse := oauth2.NewTokenResponseFromForm(callbackRequest.Form)

	LogRequest(callbackRequest)
	LogTokenPayloadln(tokenResponse)
	Logln()

	callbackStatus("Obtained authorization")

	c.PrintResult(tokenResponse)

	return nil
}
