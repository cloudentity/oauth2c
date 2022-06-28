package oauth2

import "net/url"

type Request struct {
	Method  string
	URL     *url.URL
	Headers map[string][]string
	Form    url.Values
}
