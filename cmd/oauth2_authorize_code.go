package cmd

import (
	"context"
	"net/http"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/pkg/browser"
)

func (c *OAuth2Cmd) AuthorizationCodeGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	var (
		authorizeRequest oauth2.Request
		callbackRequest  oauth2.Request
		tokenRequest     oauth2.Request
		tokenResponse    oauth2.TokenResponse
		codeVerifier     string
		err              error
	)

	LogHeader("Authorization Code Flow")

	// authorize endpoint
	LogSection("Request authorization")

	if authorizeRequest, codeVerifier, err = oauth2.RequestAuthorization(addr, clientConfig, serverConfig); err != nil {
		return err
	}

	LogRequest(authorizeRequest)

	if codeVerifier != "" {
		Logln()
		LogBox("PKCE", "code_verifier = %s\ncode_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))", codeVerifier)
	}

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

	LogRequest(callbackRequest)
	Logln()

	callbackStatus("Obtained authorization code")

	LogSection("Exchange authorization code for token")

	// token exchange
	exchangeStatus := LogAction("Exchaging authorization code for access token")

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

	c.PrintResult(tokenResponse)

	exchangeStatus("Exchanged authorization code for access token")

	return nil
}
