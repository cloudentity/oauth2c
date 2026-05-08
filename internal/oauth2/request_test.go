package oauth2_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cloudentity/oauth2c/internal/oauth2"
)

func TestAuthorizeRequestResource(t *testing.T) {
	tests := map[string]struct {
		resource []string
		expected []string
	}{
		"none": {
			resource: nil,
			expected: nil,
		},
		"single": {
			resource: []string{"https://api.example.com"},
			expected: []string{"https://api.example.com"},
		},
		"multiple": {
			resource: []string{"https://api.example.com", "https://other.example.com"},
			expected: []string{"https://api.example.com", "https://other.example.com"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := &oauth2.Request{}
			cconfig := oauth2.ClientConfig{
				ClientID:    "test-client",
				RedirectURL: "http://localhost/callback",
				Resource:    tc.resource,
			}

			_, err := r.AuthorizeRequest(cconfig, oauth2.ServerConfig{}, http.DefaultClient)
			require.NoError(t, err)

			require.Equal(t, tc.expected, r.Form["resource"])
		})
	}
}

func TestRequestTokenResource(t *testing.T) {
	tests := map[string]struct {
		resource []string
		expected []string
	}{
		"none": {
			resource: nil,
			expected: nil,
		},
		"single": {
			resource: []string{"https://api.example.com"},
			expected: []string{"https://api.example.com"},
		},
		"multiple": {
			resource: []string{"https://api.example.com", "https://other.example.com"},
			expected: []string{"https://api.example.com", "https://other.example.com"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var got url.Values

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)

				got, err = url.ParseQuery(string(body))
				require.NoError(t, err)

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
			}))
			defer srv.Close()

			cconfig := oauth2.ClientConfig{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				GrantType:    oauth2.ClientCredentialsGrantType,
				AuthMethod:   oauth2.ClientSecretPostAuthMethod,
				Resource:     tc.resource,
			}
			sconfig := oauth2.ServerConfig{TokenEndpoint: srv.URL}

			_, _, err := oauth2.RequestToken(context.Background(), cconfig, sconfig, &http.Client{})
			require.NoError(t, err)

			require.Equal(t, tc.expected, got["resource"])
		})
	}
}
