package cmd

import (
	"strings"

	"github.com/maordavidov/oauth2c/pkg/oauth2"
)

type Config struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret"`
	OpenIDDiscoveryEndpoint string `json:"openid_discovery_endpoint"`
}

func (c Config) ToClientConfig() oauth2.ClientConfig {
	return oauth2.ClientConfig{
		IssuerURL:    strings.TrimSuffix(c.OpenIDDiscoveryEndpoint, oauth2.OpenIDConfigurationPath),
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
	}
}
