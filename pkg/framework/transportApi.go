package framework

import (
	"fmt"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/go-http-utils/headers"
	"net/http"
)

type AuthedTransportApi struct {
	ApiKey      string
	AccessToken string
	Wrapped     http.RoundTripper
}

func (t *AuthedTransportApi) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.AccessToken != "" {
		req.Header.Add(headers.Authorization, fmt.Sprintf("%s%s", util.HeaderOauthToken, t.AccessToken))
	} else if t.ApiKey != "" {
		req.Header.Set(util.HeaderTpplApikey, t.ApiKey)
	}
	return t.Wrapped.RoundTrip(req)
}
