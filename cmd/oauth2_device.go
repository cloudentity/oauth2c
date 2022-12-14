package cmd

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/pkg/browser"
)

func (c *OAuth2Cmd) DeviceGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	var (
		authorizationRequest  oauth2.Request
		authorizationResponse oauth2.DeviceAuthorizationResponse
		tokenRequest          oauth2.Request
		tokenResponse         oauth2.TokenResponse
		err                   error
	)

	LogHeader("Device Flow")

	// device authorization endpoint
	LogSection("Request device authorization")

	if authorizationRequest, authorizationResponse, err = oauth2.RequestDeviceAuthorization(context.Background(), clientConfig, serverConfig, hc); err != nil {
		return err
	}

	LogRequestAndResponse(authorizationRequest, authorizationResponse)

	Logfln("\nOpen the following URL:\n\n%s\n", authorizationResponse.VerificationURIComplete)

	if err = browser.OpenURL(authorizationResponse.VerificationURIComplete); err != nil {
		LogError(err)
	}

	Logln()

	// polling

	tokenStatus := LogAction("Waiting for token. Go to the browser to authenticate...")

	ticker := time.NewTicker(time.Duration(authorizationResponse.Interval) * time.Second)
	done := make(chan bool)

	go func() {
		var oauth2Error *oauth2.Error

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if tokenRequest, tokenResponse, err = oauth2.RequestToken(
					context.Background(),
					clientConfig,
					serverConfig,
					hc,
					oauth2.WithDeviceCode(authorizationResponse.DeviceCode),
				); err != nil {
					if errors.As(err, &oauth2Error) {
						switch oauth2Error.ErrorCode {
						case oauth2.ErrAuthorizationPending, oauth2.ErrSlowDown:
							continue
						}
					}

					LogRequestAndResponseln(tokenRequest, err)
					close(done)
				} else {
					close(done)
				}
			}
		}
	}()

	<-done

	LogSection("Exchange device code for token")

	LogAuthMethod(clientConfig)
	LogRequestAndResponse(tokenRequest, tokenResponse)
	LogTokenPayloadln(tokenResponse)

	c.PrintResult(tokenResponse)

	tokenStatus("Obtained token")

	return nil
}
