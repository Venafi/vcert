package framework

import (
	"fmt"
	"github.com/go-http-utils/headers"
	"net/http"
)

type AuthedTransportApi struct {
	ApiKey         string
	OauthTokenType string
	AccessToken    string
	Wrapped        http.RoundTripper
}

func (t *AuthedTransportApi) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.AccessToken != "" {
		req.Header.Add(headers.Authorization, fmt.Sprintf("%s %s", t.OauthTokenType, t.AccessToken))
	} else if t.ApiKey != "" {
		req.Header.Set("tppl-api-key", t.ApiKey)
	}
	return t.Wrapped.RoundTrip(req)
}
