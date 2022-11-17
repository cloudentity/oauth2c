package cmd

import (
	"net/http"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/pkg/browser"
	"github.com/pterm/pterm"
)

func ImplicitGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	var (
		authorizeRequest oauth2.Request
		callbackRequest  oauth2.Request
		err              error
	)

	pterm.DefaultHeader.WithFullWidth().Println("Implicit Flow")

	// authorize endpoint
	pterm.DefaultSection.Println("Request authorization")

	if authorizeRequest, _, err = oauth2.RequestAuthorization(addr, clientConfig, serverConfig); err != nil {
		return err
	}

	LogRequest(authorizeRequest)

	pterm.Printfln("\nOpen the following URL:\n\n%s\n", authorizeRequest.URL.String())

	if err = browser.OpenURL(authorizeRequest.URL.String()); err != nil {
		pterm.Warning.PrintOnError(err)
	}

	pterm.Println()

	// callback
	callbackStatus, _ := pterm.DefaultSpinner.Start("Waiting for callback. Go to the browser to authenticate...")

	if callbackRequest, err = oauth2.WaitForCallback(addr); err != nil {
		LogRequestln(callbackRequest)
		return err
	}

	LogRequest(callbackRequest)
	LogTokenPayloadln(oauth2.NewTokenResponseFromForm(callbackRequest.Form))
	pterm.Println()

	callbackStatus.Success("Obtained authorization")

	return nil
}
