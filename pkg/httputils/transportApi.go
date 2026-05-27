package httputils

import (
	"fmt"
	"net/http"

	"github.com/Venafi/vcert/v5/pkg/util"
)

type AuthedTransportApi struct {
	ApiKey      string
	AccessToken string
	Wrapped     http.RoundTripper
	UserAgent   string
}

func (t *AuthedTransportApi) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.AccessToken != "" {
		req.Header.Add(Authorization, fmt.Sprintf("%s %s", util.OauthTokenType, t.AccessToken))
	} else if t.ApiKey != "" {
		req.Header.Set(util.HeaderTpplApikey, t.ApiKey)
	}
	req.Header.Set(UserAgent, t.UserAgent)

	return t.Wrapped.RoundTrip(req)
}
