package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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
		code = r.URL.Query().Get("code")

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`You have successfully logged in. You may close this browser.`))

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

func ExchangeCode(
	ctx context.Context,
	addr string,
	code string,
	cconfig ClientConfig,
	sconfig ServerConfig,
	hc *http.Client,
) (output map[string]interface{}, err error) {
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
		return nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if resp, err = hc.Do(req); err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if body, err = ioutil.ReadAll(resp.Body); err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("failed to exchange code for token: %d %s", resp.StatusCode, string(body))
	}

	if body, err = io.ReadAll(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read exchange response body: %w", err)
	}

	if err = json.Unmarshal(body, &output); err != nil {
		return nil, fmt.Errorf("failed to parse exchange response: %w", err)
	}

	return output, nil
}
