package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
)

const OpenIDConfigurationPath = "/.well-known/openid-configuration"

type ServerConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func FetchOpenIDConfiguration(ctx context.Context, issuerURL string, hc *http.Client) (request Request, c ServerConfig, err error) {
	var (
		req  *http.Request
		resp *http.Response
	)

	if req, err = http.NewRequestWithContext(ctx, http.MethodGet, issuerURL+OpenIDConfigurationPath, nil); err != nil {
		return request, c, err
	}

	request.Method = req.Method
	request.URL = req.URL

	if resp, err = hc.Do(req); err != nil {
		return request, c, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return request, c, ParseError(resp)
	}

	if err = json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return request, c, err
	}

	return request, c, nil
}
