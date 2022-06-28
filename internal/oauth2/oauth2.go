package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
)

type ClientConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
}

func BuildAuthorizeURL(addr string, cconfig ClientConfig, sconfig ServerConfig) (u *url.URL, err error) {
	if u, err = url.Parse(sconfig.AuthorizationEndpoint); err != nil {
		return nil, errors.Wrapf(err, "failed to parse authorization endpoint")
	}

	values := url.Values{
		"client_id":     {cconfig.ClientID},
		"response_type": {"code"},
		"redirect_uri":  {"http://" + addr + "/callback"},
	}

	u.RawQuery = values.Encode()

	return u, nil
}

func WaitForCallback(addr string) (code string, err error) {
	var (
		srv = http.Server{Addr: addr}
		wg  sync.WaitGroup
	)

	wg.Add(1)

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("error") != "" {
			err = &Error{
				ErrorCode:   r.URL.Query().Get("error"),
				Description: r.URL.Query().Get("error_description"),
				Hint:        r.URL.Query().Get("error_hint"),
				TraceID:     r.URL.Query().Get("trace_id"),
			}

			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`Authorization failed. You may close this browser.`))
		} else {
			code = r.URL.Query().Get("code")

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`Authorization succeeded. You may close this browser.`))
		}

		time.AfterFunc(time.Second, func() { srv.Shutdown(context.Background()) })
	})

	go func() {
		defer wg.Done()

		if serr := srv.ListenAndServe(); serr != http.ErrServerClosed {
			err = serr
		}
	}()

	wg.Wait()

	return code, err
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

func ExchangeCode(
	ctx context.Context,
	addr string,
	code string,
	cconfig ClientConfig,
	sconfig ServerConfig,
	hc *http.Client,
) (response TokenResponse, err error) {
	var (
		req  *http.Request
		resp *http.Response
		body []byte
	)

	values := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {cconfig.ClientID},
		"client_secret": {cconfig.ClientSecret},
		"redirect_uri":  {"http://" + addr + "/callback"},
	}

	if req, err = http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		sconfig.TokenEndpoint,
		strings.NewReader(values.Encode()),
	); err != nil {
		return response, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if resp, err = hc.Do(req); err != nil {
		return response, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return response, ParseError(resp)
	}

	if body, err = io.ReadAll(resp.Body); err != nil {
		return response, fmt.Errorf("failed to read exchange response body: %w", err)
	}

	if err = json.Unmarshal(body, &response); err != nil {
		return response, fmt.Errorf("failed to parse exchange response: %w", err)
	}

	return response, nil
}
