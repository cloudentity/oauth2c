package oauth2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/lithammer/shortuuid/v4"
	"github.com/pkg/errors"
)

// grant types
const (
	AuthorizationCodeGrantType string = "authorization_code"
	ClientCredentialsGrantType string = "client_credentials"
	ImplicitGrantType          string = "implicit"
	PasswordGrantType          string = "password"
	RefreshTokenGrantType      string = "refresh_token"
	JWTBearerGrantType         string = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	TokenExchangeGrantType     string = "urn:ietf:params:oauth:grant-type:token-exchange"
	DeviceGrantType            string = "urn:ietf:params:oauth:grant-type:device_code"
	// CIBAGrantType              string = "urn:openid:params:grant-type:ciba"
)

// auth methods
const (
	ClientSecretBasicAuthMethod string = "client_secret_basic"
	ClientSecretPostAuthMethod  string = "client_secret_post"
	ClientSecretJwtAuthMethod   string = "client_secret_jwt"
	PrivateKeyJwtAuthMethod     string = "private_key_jwt"
	SelfSignedTLSAuthMethod     string = "self_signed_tls_client_auth"
	TLSClientAuthMethod         string = "tls_client_auth"
	NoneAuthMethod              string = "none"
)

// client assertion types
const (
	JwtBearerClientAssertion string = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

const CodeVerifierLength = 43

var CodeChallengeEncoder = base64.RawURLEncoding

type ClientConfig struct {
	IssuerURL        string
	GrantType        string
	ClientID         string
	ClientSecret     string
	Scopes           []string
	AuthMethod       string
	PKCE             bool
	PAR              bool
	Insecure         bool
	ResponseType     []string
	ResponseMode     string
	Username         string
	Password         string
	RefreshToken     string
	Assertion        string
	SigningKey       string
	EncryptionKey    string
	SubjectToken     string
	SubjectTokenType string
	ActorToken       string
	ActorTokenType   string
	TLSCert          string
	TLSKey           string
	TLSRootCA        string
}

func NewAuthorizationRequest(addr string, cconfig ClientConfig) (values url.Values, codeVerifier string, err error) {
	values = url.Values{
		"client_id":    {cconfig.ClientID},
		"redirect_uri": {"http://" + addr + "/callback"},
		"state":        {shortuuid.New()},
		"nonce":        {shortuuid.New()},
	}

	if len(cconfig.ResponseType) > 0 {
		values.Set("response_type", strings.Join(cconfig.ResponseType, " "))
	}

	if cconfig.ResponseMode != "" {
		values.Set("response_mode", cconfig.ResponseMode)
	}

	if len(cconfig.Scopes) > 0 {
		values.Set("scope", strings.Join(cconfig.Scopes, " "))
	}

	if cconfig.PKCE {
		codeVerifier = RandomString(CodeVerifierLength)

		hash := sha256.New()

		if _, err = hash.Write([]byte(codeVerifier)); err != nil {
			return values, "", err
		}

		codeChallenge := CodeChallengeEncoder.EncodeToString(hash.Sum([]byte{}))

		values.Set("code_challenge", codeChallenge)
		values.Set("code_challenge_method", "S256")
	}

	return values, codeVerifier, nil
}

func RequestAuthorization(addr string, cconfig ClientConfig, sconfig ServerConfig) (r Request, codeVerifier string, err error) {
	var values url.Values

	if r.URL, err = url.Parse(sconfig.AuthorizationEndpoint); err != nil {
		return r, "", errors.Wrapf(err, "failed to parse authorization endpoint")
	}

	if values, codeVerifier, err = NewAuthorizationRequest(addr, cconfig); err != nil {
		return r, "", errors.Wrapf(err, "failed to create authorization request")
	}

	r.URL.RawQuery = values.Encode()
	r.Method = http.MethodGet

	return r, codeVerifier, nil
}

type PARResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

func RequestPAR(
	ctx context.Context,
	addr string,
	cconfig ClientConfig,
	sconfig ServerConfig,
	hc *http.Client,
) (parRequest Request, parResponse PARResponse, authorizeRequest Request, codeVerifier string, err error) {
	var (
		req      *http.Request
		resp     *http.Response
		endpoint string
	)

	// push authorization request to /par
	if parRequest.Form, codeVerifier, err = NewAuthorizationRequest(addr, cconfig); err != nil {
		return parRequest, parResponse, authorizeRequest, "", errors.Wrapf(err, "failed to create authorization request")
	}

	if endpoint, err = parRequest.AuthenticateClient(
		sconfig.PushedAuthorizationRequestEndpoint,
		sconfig.MTLsEndpointAliases.PushedAuthorizationRequestEndpoint,
		cconfig,
		sconfig,
		hc,
	); err != nil {
		return parRequest, parResponse, authorizeRequest, "", errors.Wrapf(err, "failed to create client authentication request")
	}

	if req, err = http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(parRequest.Form.Encode()),
	); err != nil {
		return parRequest, parResponse, authorizeRequest, codeVerifier, err
	}

	if cconfig.AuthMethod == ClientSecretBasicAuthMethod {
		req.SetBasicAuth(cconfig.ClientID, cconfig.ClientSecret)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	parRequest.Method = req.Method
	parRequest.Headers = req.Header
	parRequest.URL = req.URL

	if resp, err = hc.Do(req); err != nil {
		return parRequest, parResponse, authorizeRequest, codeVerifier, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return parRequest, parResponse, authorizeRequest, codeVerifier, ParseError(resp)
	}

	if err = json.NewDecoder(resp.Body).Decode(&parResponse); err != nil {
		return parRequest, parResponse, authorizeRequest, codeVerifier, fmt.Errorf("failed to parse token response: %w", err)
	}

	// build request to /authorize
	if authorizeRequest.URL, err = url.Parse(sconfig.AuthorizationEndpoint); err != nil {
		return parRequest, parResponse, authorizeRequest, codeVerifier, errors.Wrapf(err, "failed to create authorization request")
	}

	values := url.Values{
		"client_id":   {cconfig.ClientID},
		"request_uri": {parResponse.RequestURI},
	}

	authorizeRequest.URL.RawQuery = values.Encode()
	authorizeRequest.Method = http.MethodGet

	return parRequest, parResponse, authorizeRequest, codeVerifier, nil
}

func WaitForCallback(clientConfig ClientConfig, serverConfig ServerConfig, addr string, hc *http.Client) (request Request, err error) {
	var (
		srv           = http.Server{Addr: addr}
		signingKey    jose.JSONWebKey
		encryptionKey jose.JSONWebKey
		wg            sync.WaitGroup
	)

	wg.Add(1)

	if signingKey, err = ReadKey(SigningKey, serverConfig.JWKsURI, hc); err != nil {
		return request, errors.Wrapf(err, "failed to read signing key from %s", serverConfig.JWKsURI)
	}

	if clientConfig.EncryptionKey != "" {
		if encryptionKey, err = ReadKey(EncryptionKey, clientConfig.EncryptionKey, hc); err != nil {
			return request, errors.Wrapf(err, "failed to read encryption key from %s", clientConfig.EncryptionKey)
		}
	}

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			time.AfterFunc(time.Second, func() {
				if err := srv.Shutdown(context.Background()); err != nil {
					log.Fatal(err)
				}
			})
		}()

		if err = r.ParseForm(); err != nil {
			log.Fatal(err)
			return
		}

		request.Method = r.Method
		request.URL = r.URL
		request.Form = r.PostForm

		if err = request.ParseJARM(signingKey, encryptionKey); err != nil {
			log.Fatal(err)
			return
		}

		w.Header().Add("Content-Type", "text/html")

		if request.Get("error") != "" {
			err = &Error{
				ErrorCode:   request.Get("error"),
				Description: request.Get("error_description"),
				Hint:        request.Get("error_hint"),
				TraceID:     request.Get("trace_id"),
			}

			w.WriteHeader(http.StatusBadRequest)

			if _, err := w.Write([]byte(`<script>window.close()</script> Authorization failed. You may close this window.`)); err != nil {
				log.Fatal(err)
			}
		} else {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`<script>window.close()</script> Authorization succeeded. You may close this window.`)); err != nil {
				log.Fatal(err)
			}
		}
	})

	go func() {
		defer wg.Done()

		if serr := srv.ListenAndServe(); serr != http.ErrServerClosed {
			err = serr
		}
	}()

	wg.Wait()

	return request, err
}

type TokenResponse struct {
	AccessToken     string `json:"access_token,omitempty"`
	ExpiresIn       int64  `json:"expires_in,omitempty"`
	IDToken         string `json:"id_token,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	Scope           string `json:"scope,omitempty"`
	TokenType       string `json:"token_type,omitempty"`
}

func NewTokenResponseFromForm(f url.Values) TokenResponse {
	expiresIn, _ := strconv.ParseInt(f.Get("expires_in"), 10, 64)

	return TokenResponse{
		AccessToken:     f.Get("access_token"),
		ExpiresIn:       expiresIn,
		IDToken:         f.Get("id_token"),
		IssuedTokenType: f.Get("issued_token_type"),
		RefreshToken:    f.Get("refresh_token"),
		Scope:           f.Get("scope"),
		TokenType:       f.Get("token_type"),
	}
}

type RequestTokenParams struct {
	Code         string
	DeviceCode   string
	CodeVerifier string
	RedirectURL  string
}

type RequestTokenOption func(*RequestTokenParams)

func WithAuthorizationCode(code string) func(*RequestTokenParams) {
	return func(opts *RequestTokenParams) {
		opts.Code = code
	}
}

func WithDeviceCode(deviceCode string) func(*RequestTokenParams) {
	return func(opts *RequestTokenParams) {
		opts.DeviceCode = deviceCode
	}
}

func WithCodeVerifier(codeVerifier string) func(*RequestTokenParams) {
	return func(opts *RequestTokenParams) {
		opts.CodeVerifier = codeVerifier
	}
}

func WithRedirectURL(url string) func(*RequestTokenParams) {
	return func(opts *RequestTokenParams) {
		opts.RedirectURL = url
	}
}

func RequestToken(
	ctx context.Context,
	cconfig ClientConfig,
	sconfig ServerConfig,
	hc *http.Client,
	opts ...RequestTokenOption,
) (request Request, response TokenResponse, err error) {
	var (
		req      *http.Request
		resp     *http.Response
		params   RequestTokenParams
		endpoint string
		body     []byte
	)

	for _, opt := range opts {
		opt(&params)
	}

	request.Form = url.Values{
		"grant_type": {cconfig.GrantType},
	}

	switch cconfig.GrantType {
	case ClientCredentialsGrantType, PasswordGrantType, RefreshTokenGrantType, JWTBearerGrantType:
		request.Form.Set("scope", strings.Join(cconfig.Scopes, " "))
	}

	switch cconfig.GrantType {
	case PasswordGrantType:
		request.Form.Set("username", cconfig.Username)
		request.Form.Set("password", cconfig.Password)
	case RefreshTokenGrantType:
		request.Form.Set("refresh_token", cconfig.RefreshToken)
	case JWTBearerGrantType:
		var assertion string

		if assertion, request.Key, err = SignJWT(
			AssertionClaims(sconfig, cconfig),
			JWKSigner(cconfig, hc),
		); err != nil {
			return request, response, err
		}

		request.Form.Set("assertion", assertion)
	case TokenExchangeGrantType:
		request.Form.Set("subject_token", cconfig.SubjectToken)
		request.Form.Set("subject_token_type", cconfig.SubjectTokenType)

		if cconfig.ActorToken != "" {
			request.Form.Set("actor_token", cconfig.ActorToken)
			request.Form.Set("actor_token_type", cconfig.ActorTokenType)
		}
	case DeviceGrantType:
		request.Form.Set("device_code", params.DeviceCode)
	}

	if endpoint, err = request.AuthenticateClient(
		sconfig.TokenEndpoint,
		sconfig.MTLsEndpointAliases.TokenEndpoint,
		cconfig,
		sconfig,
		hc,
	); err != nil {
		return request, response, err
	}

	if params.RedirectURL != "" {
		request.Form.Set("redirect_uri", params.RedirectURL)
	}

	if params.Code != "" {
		request.Form.Set("code", params.Code)
	}

	if params.CodeVerifier != "" {
		request.Form.Set("code_verifier", params.CodeVerifier)
	}

	if req, err = http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(request.Form.Encode()),
	); err != nil {
		return request, response, err
	}

	if cconfig.AuthMethod == ClientSecretBasicAuthMethod {
		req.SetBasicAuth(cconfig.ClientID, cconfig.ClientSecret)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	request.Method = req.Method
	request.Headers = req.Header
	request.URL = req.URL

	if resp, err = hc.Do(req); err != nil {
		return request, response, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return request, response, ParseError(resp)
	}

	if body, err = io.ReadAll(resp.Body); err != nil {
		return request, response, fmt.Errorf("failed to read exchange response body: %w", err)
	}

	if err = json.Unmarshal(body, &response); err != nil {
		return request, response, fmt.Errorf("failed to parse exchange response: %w", err)
	}

	return request, response, nil
}
