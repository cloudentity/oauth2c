package cmd

import (
	"context"
	"net/http"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/pkg/browser"
	"github.com/pterm/pterm"
)

func AuthorizationCodeGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	var (
		authorizeRequest oauth2.Request
		callbackRequest  oauth2.Request
		tokenRequest     oauth2.Request
		tokenResponse    oauth2.TokenResponse
		codeVerifier     string
		err              error
	)

	pterm.DefaultHeader.WithFullWidth().Println("Authorization Code Flow")

	// authorize endpoint
	pterm.DefaultSection.Println("Request authorization")

	if authorizeRequest, codeVerifier, err = oauth2.RequestAuthorization(addr, clientConfig, serverConfig); err != nil {
		return err
	}

	LogRequest(authorizeRequest)

	if codeVerifier != "" {
		pterm.Println()
		pterm.DefaultBox.WithTitle("PKCE").Printfln("code_verifier = %s\ncode_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))", codeVerifier)
	}

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
	pterm.Println()

	callbackStatus.Success("Obtained authorization code")

	pterm.DefaultSection.Println("Exchange authorization code for token")

	// token exchange
	exchangeStatus, _ := pterm.DefaultSpinner.Start("Exchaging authorization code for access token")

	if tokenRequest, tokenResponse, err = oauth2.RequestToken(
		context.Background(),
		clientConfig,
		serverConfig,
		hc,
		oauth2.WithAuthorizationCode(callbackRequest.Get("code")),
		oauth2.WithRedirectURL("http://"+addr+"/callback"),
		oauth2.WithCodeVerifier(codeVerifier),
	); err != nil {
		LogRequestAndResponseln(tokenRequest, err)
		return err
	}

	LogAuthMethod(clientConfig)
	LogRequestAndResponse(tokenRequest, tokenResponse)
	LogTokenPayloadln(tokenResponse)

	exchangeStatus.Success("Exchanged authorization code for access token")

	return nil
}
