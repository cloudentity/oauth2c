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
	// CIBAGrantType              string = "urn:openid:params:grant-type:ciba"
	// TokenExchangeGrantType     string = "urn:ietf:params:oauth:grant-type:token-exchange"
	// DeviceGrantType            string = "urn:ietf:params:oauth:grant-type:device_code"
)

// auth methods
const (
	ClientSecretBasicAuthMethod string = "client_secret_basic"
	ClientSecretPostAuthMethod  string = "client_secret_post"
	// ClientSecretJwtAuthMethod   string = "client_secret_jwt"
	// PrivateKeyJwtAuthMethod     string = "private_key_jwt"
	// SelfSignedTLSAuthMethod     string = "self_signed_tls_client_auth"
	// TLSClientAuthMethod         string = "tls_client_auth"
	// NoneAuthMethod              string = "none"
)

const CodeVerifierLength = 43

var CodeChallengeEncoder = base64.RawURLEncoding

type ClientConfig struct {
	IssuerURL    string
	GrantType    string
	ClientID     string
	ClientSecret string
	Scopes       []string
	AuthMethod   string
	PKCE         bool
	NoPKCE       bool
	Insecure     bool
	ResponseType []string
	ResponseMode string
	Username     string
	Password     string
	RefreshToken string
	Assertion    string
	SigningKey   string
}

func RequestAuthorization(addr string, cconfig ClientConfig, sconfig ServerConfig) (r Request, codeVerifier string, err error) {
	if r.URL, err = url.Parse(sconfig.AuthorizationEndpoint); err != nil {
		return r, "", errors.Wrapf(err, "failed to parse authorization endpoint")
	}

	values := url.Values{
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
			return r, "", err
		}

		codeChallenge := CodeChallengeEncoder.EncodeToString(hash.Sum([]byte{}))

		values.Set("code_challenge", codeChallenge)
		values.Set("code_challenge_method", "S256")
	}

	r.URL.RawQuery = values.Encode()
	r.Method = http.MethodGet

	return r, codeVerifier, nil
}

func WaitForCallback(addr string) (request Request, err error) {
	var (
		srv = http.Server{Addr: addr}
		wg  sync.WaitGroup
	)

	wg.Add(1)

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			time.AfterFunc(time.Second, func() {
				if err := srv.Shutdown(context.Background()); err != nil {
					log.Fatal(err)
				}
			})
		}()

		if err = r.ParseForm(); err != nil {
			return
		}

		request.Method = r.Method
		request.URL = r.URL
		request.Form = r.PostForm

		if r.URL.Query().Get("error") != "" {
			err = &Error{
				ErrorCode:   r.URL.Query().Get("error"),
				Description: r.URL.Query().Get("error_description"),
				Hint:        r.URL.Query().Get("error_hint"),
				TraceID:     r.URL.Query().Get("trace_id"),
			}

			w.WriteHeader(http.StatusBadRequest)

			if _, err := w.Write([]byte(`Authorization failed. You may close this browser.`)); err != nil {
				log.Fatal(err)
			}
		} else {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`Authorization succeeded. You may close this browser.`)); err != nil {
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
	CodeVerifier string
	RedirectURL  string
	Assertion    string
}

type RequestTokenOption func(*RequestTokenParams)

func WithAuthorizationCode(code string) func(*RequestTokenParams) {
	return func(opts *RequestTokenParams) {
		opts.Code = code
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

func WithAssertion(assertion string) func(*RequestTokenParams) {
	return func(opts *RequestTokenParams) {
		opts.Assertion = assertion
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
		req    *http.Request
		resp   *http.Response
		params RequestTokenParams
		body   []byte
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
	}

	switch cconfig.AuthMethod {
	case ClientSecretPostAuthMethod:
		request.Form.Set("client_id", cconfig.ClientID)
		request.Form.Set("client_secret", cconfig.ClientSecret)
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

	if params.Assertion != "" {
		request.Form.Set("assertion", params.Assertion)
	}

	if req, err = http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		sconfig.TokenEndpoint,
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
