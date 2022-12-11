package cmd

import (
	"context"
	"net/http"

	"github.com/cloudentity/oauth2c/internal/oauth2"
)

func ClientCredentialsGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return tokenEndpointFlow("Client Credentials Flow", clientConfig, serverConfig, hc)
}

func PasswordGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return tokenEndpointFlow("Resource Owner Password Credentials Flow", clientConfig, serverConfig, hc)
}

func RefreshTokenGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return tokenEndpointFlow("Refresh Token Flow", clientConfig, serverConfig, hc)
}

func JWTBearerGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return tokenEndpointFlow("JWT Bearer Grant Flow", clientConfig, serverConfig, hc)
}

func tokenEndpointFlow(
	name string,
	clientConfig oauth2.ClientConfig,
	serverConfig oauth2.ServerConfig,
	hc *http.Client,
	requestTokenOpts ...oauth2.RequestTokenOption,
) error {

	var (
		tokenRequest  oauth2.Request
		tokenResponse oauth2.TokenResponse
		err           error
	)

	LogHeader(name)

	// request token
	LogSection("Request authorization")

	authorizationStatus := LogAction("Requesting authorization")

	if tokenRequest, tokenResponse, err = oauth2.RequestToken(
		context.Background(),
		clientConfig,
		serverConfig,
		hc,
		requestTokenOpts...,
	); err != nil {
		LogRequestAndResponseln(tokenRequest, err)
		return err
	}

	LogAssertion(tokenRequest, "Assertion", "assertion")
	LogAssertion(tokenRequest, "Client assertion", "client_assertion")
	LogAuthMethod(clientConfig)
	LogRequestAndResponse(tokenRequest, tokenResponse)
	LogTokenPayloadln(tokenResponse)
	LogResult(tokenResponse)

	authorizationStatus("Authorization completed")

	return nil
}
