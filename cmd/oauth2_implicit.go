package cmd

import (
	"net/http"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/pkg/browser"
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

	if authorizeRequest, _, err = oauth2.RequestAuthorization(addr, clientConfig, serverConfig); err != nil {
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

	if callbackRequest, err = oauth2.WaitForCallback(addr); err != nil {
		LogRequestln(callbackRequest)
		return err
	}

	tokenResponse := oauth2.NewTokenResponseFromForm(callbackRequest.Form)

	LogRequest(callbackRequest)
	LogTokenPayloadln(tokenResponse)
	Logln()

	c.PrintResult(tokenResponse)

	callbackStatus("Obtained authorization")

	return nil
}
