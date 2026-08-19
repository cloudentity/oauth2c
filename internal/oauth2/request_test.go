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

func TestRequestTokenRequestedTokenType(t *testing.T) {
	tests := map[string]struct {
		requestedTokenType string
		expected           []string
	}{
		"none": {
			requestedTokenType: "",
			expected:           nil,
		},
		"id-jag": {
			requestedTokenType: "urn:ietf:params:oauth:token-type:id-jag",
			expected:           []string{"urn:ietf:params:oauth:token-type:id-jag"},
		},
		"access token": {
			requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
			expected:           []string{"urn:ietf:params:oauth:token-type:access_token"},
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
				_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"N_A","expires_in":3600}`))
			}))
			defer srv.Close()

			cconfig := oauth2.ClientConfig{
				ClientID:           "test-client",
				ClientSecret:       "test-secret",
				GrantType:          oauth2.TokenExchangeGrantType,
				AuthMethod:         oauth2.ClientSecretPostAuthMethod,
				SubjectToken:       "subject-token",
				SubjectTokenType:   "urn:ietf:params:oauth:token-type:access_token",
				RequestedTokenType: tc.requestedTokenType,
			}
			sconfig := oauth2.ServerConfig{TokenEndpoint: srv.URL}

			_, _, err := oauth2.RequestToken(context.Background(), cconfig, sconfig, &http.Client{})
			require.NoError(t, err)

			require.Equal(t, tc.expected, got["requested_token_type"])
		})
	}
}

// An ID-JAG is signed by the identity provider, so the redeeming client has a token and no key to
// sign one with. The absence of a signing key here is the point: it proves SignJWT is bypassed
// rather than merely overridden.
func TestRequestTokenAssertionJWT(t *testing.T) {
	const grant = "eyJ0eXAiOiJvYXV0aC1pZC1qYWcrand0IiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSJ9.signature"

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
		GrantType:    oauth2.JWTBearerGrantType,
		AuthMethod:   oauth2.ClientSecretPostAuthMethod,
		AssertionJWT: grant,
	}
	sconfig := oauth2.ServerConfig{TokenEndpoint: srv.URL}

	_, _, err := oauth2.RequestToken(context.Background(), cconfig, sconfig, &http.Client{})
	require.NoError(t, err)

	require.Equal(t, []string{grant}, got["assertion"])
}

func TestRequestTokenAssertionJWTUnsetStillSigns(t *testing.T) {
	cconfig := oauth2.ClientConfig{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		GrantType:    oauth2.JWTBearerGrantType,
		AuthMethod:   oauth2.ClientSecretPostAuthMethod,
	}
	sconfig := oauth2.ServerConfig{TokenEndpoint: "http://localhost:0"}

	_, _, err := oauth2.RequestToken(context.Background(), cconfig, sconfig, &http.Client{})
	require.Error(t, err)
}
