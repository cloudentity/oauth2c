package oauth2

import (
	"crypto/x509"
	"net/url"
)

type Request struct {
	Method  string
	URL     *url.URL
	Headers map[string][]string
	Form    url.Values
	Key     interface{}
	Cert    *x509.Certificate
}

func (r *Request) Get(key string) string {
	if v := r.URL.Query().Get(key); v != "" {
		return v
	}

	return r.Form.Get(key)
}
