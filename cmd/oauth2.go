package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt"
	"github.com/imdario/mergo"
	"github.com/pkg/browser"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var (
	cconfig oauth2.ClientConfig
	addr    = "localhost:9876"
	parser  jwt.Parser
)

func init() {
	OAuth2Cmd.PersistentFlags().StringVar(&cconfig.ClientID, "client-id", "", "client identifier")
	OAuth2Cmd.PersistentFlags().StringVar(&cconfig.ClientSecret, "client-secret", "", "client secret")
	OAuth2Cmd.PersistentFlags().StringVar(&cconfig.GrantType, "grant-type", "", "grant type")
	OAuth2Cmd.PersistentFlags().StringVar(&cconfig.AuthMethod, "auth-method", "", "token endpoint authentication method")
	OAuth2Cmd.PersistentFlags().StringVar(&cconfig.Username, "username", "", "resource owner password credentials grant flow username")
	OAuth2Cmd.PersistentFlags().StringVar(&cconfig.Password, "password", "", "resource owner password credentials grant flow password")
	OAuth2Cmd.PersistentFlags().StringVar(&cconfig.RefreshToken, "refresh-token", "", "refresh token")
	OAuth2Cmd.PersistentFlags().StringSliceVar(&cconfig.ResponseType, "response-types", []string{""}, "response type")
	OAuth2Cmd.PersistentFlags().StringVar(&cconfig.ResponseMode, "response-mode", "", "response mode")
	OAuth2Cmd.PersistentFlags().StringSliceVar(&cconfig.Scopes, "scopes", []string{}, "requested scopes")
	OAuth2Cmd.PersistentFlags().BoolVar(&cconfig.PKCE, "pkce", false, "enable proof key for code exchange (PKCE)")
	OAuth2Cmd.PersistentFlags().BoolVar(&cconfig.NoPKCE, "no-pkce", false, "disable proof key for code exchange (PKCE)")
	OAuth2Cmd.PersistentFlags().StringVar(&cconfig.Assertion, "assertion", "", "claims for jwt bearer assertion (standard claims such as iss, aud, iat, exp, jti are automatically generated)")
	OAuth2Cmd.PersistentFlags().StringVar(&cconfig.SigningKey, "signing-key", "", "path or url to signing key in jwks format")
	OAuth2Cmd.PersistentFlags().BoolVar(&cconfig.Insecure, "insecure", false, "allow insecure connections")
}

var OAuth2Cmd = &cobra.Command{
	Use:   "oauthc [issuer url or json config file]",
	Short: "User-friendly command-line for OAuth2",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var (
			config Config
			data   []byte
			err    error
		)

		if data, err = os.ReadFile(args[0]); err == nil {
			if err = json.Unmarshal(data, &config); err != nil {
				pterm.Error.PrintOnError(err)
				os.Exit(1)
			}

			if err := mergo.Merge(&cconfig, config.ToClientConfig()); err != nil {
				pterm.Error.PrintOnError(err)
				os.Exit(1)
			}
		} else {
			cconfig.IssuerURL = strings.TrimSuffix(args[0], oauth2.OpenIDConfigurationPath)
		}

		hc := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: cconfig.Insecure,
				},
			},
		}

		if err := Authorize(cconfig, hc); err != nil {
			var oauth2Error *oauth2.Error

			if errors.As(err, &oauth2Error) {
				switch oauth2Error.Hint {
				case "Clients must include a code_challenge when performing the authorize code flow, but it is missing.":
					pterm.Warning.Println("Authorization server enforces PKCE. Use --pkce flag.")
				}
			}

			pterm.Error.PrintOnError(err)
			os.Exit(1)
		}
	},
}

func PromptForClientConfig(client oauth2.ClientConfig, server oauth2.ServerConfig) oauth2.ClientConfig {
	// grant type
	if client.GrantType == "" {
		client.GrantType = PromptStringSlice("Grant type", server.SupportedGrantTypes)
	}

	// auth method
	switch client.GrantType {
	case oauth2.AuthorizationCodeGrantType, oauth2.ClientCredentialsGrantType, oauth2.RefreshTokenGrantType, oauth2.PasswordGrantType, oauth2.JWTBearerGrantType:
		if client.AuthMethod == "" {
			client.AuthMethod = PromptStringSlice("Token endpoint auth method", server.SupportedTokenEndpointAuthMethods)
		}
	}

	// scopes
	switch client.GrantType {
	case oauth2.AuthorizationCodeGrantType, oauth2.ClientCredentialsGrantType, oauth2.ImplicitGrantType, oauth2.PasswordGrantType, oauth2.JWTBearerGrantType:
		if len(client.Scopes) == 0 || client.Scopes[0] == "" {
			client.Scopes = PromptMultiStringSlice("Scopes", server.SupportedScopes)
		}
	}

	// response types
	switch client.GrantType {
	case oauth2.AuthorizationCodeGrantType, oauth2.ImplicitGrantType:
		if len(client.ResponseType) == 0 || client.ResponseType[0] == "" {
			client.ResponseType = PromptMultiStringSlice("Response types", server.SupportedResponseTypes)
		}
	}

	// response mode
	switch client.GrantType {
	case oauth2.AuthorizationCodeGrantType, oauth2.ImplicitGrantType:
		if client.ResponseMode == "" {
			client.ResponseMode = PromptStringSlice("Response mode", server.SupportedResponseModes)
		}
	}

	// pkce
	switch client.GrantType {
	case oauth2.AuthorizationCodeGrantType:
		if !client.PKCE && !client.NoPKCE {
			client.PKCE = PromptBool("PKCE")
		}
	}

	if client.ClientID == "" {
		client.ClientID = PromptString("Client ID")
	}

	// client secret
	switch client.AuthMethod {
	case oauth2.ClientSecretBasicAuthMethod, oauth2.ClientSecretPostAuthMethod:
		if client.ClientSecret == "" {
			client.ClientSecret = PromptString("Client secret")
		}
	}

	switch client.GrantType {
	case oauth2.PasswordGrantType:
		if client.Username == "" {
			client.Username = PromptString("Username")
		}

		if client.Password == "" {
			client.Password = PromptString("Password")
		}
	case oauth2.RefreshTokenGrantType:
		if client.RefreshToken == "" {
			client.RefreshToken = PromptString("Refresh token")
		}
	}

	return client
}

func Authorize(clientConfig oauth2.ClientConfig, hc *http.Client) error {
	var (
		serverRequest oauth2.Request
		serverConfig  oauth2.ServerConfig
		err           error
	)

	// openid configuration
	if serverRequest, serverConfig, err = oauth2.FetchOpenIDConfiguration(
		context.Background(),
		clientConfig.IssuerURL,
		hc,
	); err != nil {
		LogRequestln(serverRequest)
		return err
	}

	clientConfig = PromptForClientConfig(clientConfig, serverConfig)

	data := pterm.TableData{
		{"Issuer URL", clientConfig.IssuerURL},
		{"Grant type", clientConfig.GrantType},
		{"Auth method", clientConfig.AuthMethod},
		{"Scopes", strings.Join(clientConfig.Scopes, ", ")},
		{"Response types", strings.Join(clientConfig.ResponseType, ", ")},
		{"Response mode", clientConfig.ResponseMode},
		{"PKCE", strconv.FormatBool(clientConfig.PKCE)},
		{"Client ID", clientConfig.ClientID},
		{"Client secret", clientConfig.ClientSecret},
		{"Username", clientConfig.Username},
		{"Password", clientConfig.Password},
		{"Refresh token", clientConfig.RefreshToken},
	}

	nonEmptyData := pterm.TableData{}

	for _, vs := range data {
		if vs[1] != "" {
			nonEmptyData = append(nonEmptyData, vs)
		}
	}

	if err := pterm.DefaultTable.WithData(nonEmptyData).WithBoxed().Render(); err != nil {
		return err
	}

	pterm.Println()

	switch clientConfig.GrantType {
	case oauth2.AuthorizationCodeGrantType:
		return AuthorizationCodeGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.ImplicitGrantType:
		return ImplicitGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.ClientCredentialsGrantType:
		return ClientCredentialsGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.PasswordGrantType:
		return PasswordGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.RefreshTokenGrantType:
		return RefreshTokenGrantFlow(clientConfig, serverConfig, hc)
	case oauth2.JWTBearerGrantType:
		return JWTBearerGrantFlow(clientConfig, serverConfig, hc)
	}

	return fmt.Errorf("Unknown grant type: %s", clientConfig.GrantType)
}

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

func ImplicitGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	var (
		authorizeRequest oauth2.Request
		callbackRequest  oauth2.Request
		err              error
	)

	pterm.DefaultHeader.WithFullWidth().Println("Implicit Flow")

	// authorize endpoint
	pterm.DefaultSection.Println("Request authorization")

	if authorizeRequest, _, err = oauth2.RequestAuthorization(addr, clientConfig, serverConfig); err != nil {
		return err
	}

	LogRequest(authorizeRequest)

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
	LogTokenPayloadln(oauth2.NewTokenResponseFromForm(callbackRequest.Form))
	pterm.Println()

	callbackStatus.Success("Obtained authorization")

	return nil
}

func ClientCredentialsGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return tokenEndpointFlow("Client Credentials Flow", clientConfig, serverConfig, hc)
}

func PasswordGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return tokenEndpointFlow("Resource Owner Password Credentials Flow", clientConfig, serverConfig, hc)
}

func JWTBearerGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	var (
		extraClaims map[string]interface{}
		key         jose.JSONWebKey
		assertion   string
		err         error
	)

	if clientConfig.Assertion == "" {
		clientConfig.Assertion = "{}"
	}

	if err = json.Unmarshal([]byte(clientConfig.Assertion), &extraClaims); err != nil {
		return fmt.Errorf("failed to parse assertion extra claims, it must be a valid JSON: %+v", err)
	}

	if clientConfig.SigningKey == "" {
		return errors.New("path to signing key must be provided")
	}

	if key, err = oauth2.ReadKey(clientConfig.SigningKey, hc); err != nil {
		return fmt.Errorf("failed to read signing key: %s, %+v", clientConfig.SigningKey, err)
	}

	claims := oauth2.WithStandardClaims(extraClaims, serverConfig)

	if assertion, err = oauth2.SignJWT(claims, key); err != nil {
		return fmt.Errorf("failed to sign assertion: %s", clientConfig.SigningKey)
	}

	return tokenEndpointFlow("JWT Bearer Grant Flow", clientConfig, serverConfig, hc, oauth2.WithAssertion(assertion))
}

func RefreshTokenGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return tokenEndpointFlow("Refresh Token Flow", clientConfig, serverConfig, hc)
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

	pterm.DefaultHeader.WithFullWidth().Println(name)

	// request token
	pterm.DefaultSection.Println("Request authorization")

	tokenStatus, _ := pterm.DefaultSpinner.Start("Requesting authorization")

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

	LogAssertion(tokenRequest)
	LogAuthMethod(clientConfig)
	LogRequestAndResponse(tokenRequest, tokenResponse)
	LogTokenPayloadln(tokenResponse)

	tokenStatus.Success("Authorization completed")

	return nil
}
