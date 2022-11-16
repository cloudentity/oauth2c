package oauth2

import "net/url"

type Request struct {
	Method  string
	URL     *url.URL
	Headers map[string][]string
	Form    url.Values
	Key     interface{}
}

func (r *Request) Get(key string) string {
	if v := r.URL.Query().Get(key); v != "" {
		return v
	}

	return r.Form.Get(key)
}
