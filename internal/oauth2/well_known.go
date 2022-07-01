package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
)

const OpenIDConfigurationPath = "/.well-known/openid-configuration"

type ServerConfig struct {
	Issuer                            string   `json:"issuer"`
	SupportedGrantTypes               []string `json:"grant_types_supported"`
	SupportedResponseTypes            []string `json:"response_types_supported"`
	SupportedTokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	SupportedScopes                   []string `json:"scopes_supported"`
	SupportedResponseModes            []string `json:"response_modes_supported"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
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
