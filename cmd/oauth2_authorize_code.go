package cmd

import (
	"context"
	"net/http"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/pkg/browser"
)

func (c *OAuth2Cmd) AuthorizationCodeGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	var (
		parRequest       oauth2.Request
		parResponse      oauth2.PARResponse
		authorizeRequest oauth2.Request
		callbackRequest  oauth2.Request
		tokenRequest     oauth2.Request
		tokenResponse    oauth2.TokenResponse
		codeVerifier     string
		err              error
	)

	LogHeader("Authorization Code Flow")

	if clientConfig.PAR {
		LogSection("Request PAR")

		if parRequest, parResponse, authorizeRequest, codeVerifier, err = oauth2.RequestPAR(context.Background(), clientConfig, serverConfig, hc); err != nil {
			LogRequestAndResponseln(parRequest, err)
			return err
		}

		LogAssertion(parRequest, "Client assertion", "client_assertion")
		LogAuthMethod(clientConfig)
		LogRequestObject(parRequest)
		LogRequestAndResponse(parRequest, parResponse)

		LogSection("Request authorization")

		LogRequest(authorizeRequest)
	} else {
		LogSection("Request authorization")

		if authorizeRequest, codeVerifier, err = oauth2.RequestAuthorization(clientConfig, serverConfig, hc); err != nil {
			return err
		}

		LogRequestObject(authorizeRequest)
		LogRequest(authorizeRequest)
	}

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

	if callbackRequest, err = oauth2.WaitForCallback(clientConfig, serverConfig, hc); err != nil {
		LogRequestln(callbackRequest)
		return err
	}

	LogRequest(callbackRequest)
	LogJARM(callbackRequest)
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
		oauth2.WithRedirectURL(clientConfig.RedirectURL),
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
