package fake

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/Venafi/vcert/v4/test/tpp/fake/models"
	"github.com/go-logr/logr"
)

type state struct {
	sync.RWMutex
	username            string
	password            string
	refreshToken        string
	accessToken         string
	refreshTokenExpires time.Time
}

func (o *state) WithUsername(username string) *state {
	o.Lock()
	defer o.Unlock()
	o.username = username
	return o
}

func (o *state) WithPassword(password string) *state {
	o.Lock()
	defer o.Unlock()
	o.password = password
	return o
}

func (o *state) WithRefreshToken(token string) *state {
	o.Lock()
	defer o.Unlock()
	o.accessToken = token
	return o
}

func (o *state) WithAccessToken(token string) *state {
	o.Lock()
	defer o.Unlock()
	o.accessToken = token
	return o
}

type Fake struct {
	*state
	*httptest.Server
	log logr.Logger
}

func (o *Fake) Start(ctx context.Context) {
	log := logFromContext(ctx)
	log.V(1).Info("starting")
	o.Server.StartTLS()
}

func (o *Fake) Close(ctx context.Context) {
	log := logFromContext(ctx)
	log.V(1).Info("stopping")
	o.Server.Close()
}

func New(log logr.Logger) *Fake {
	mux := http.NewServeMux()
	ts := httptest.NewUnstartedServer(mux)
	f := &Fake{
		log:    log,
		state:  &state{},
		Server: ts,
	}
	mux.HandleFunc("/vedauth/authorize/oauth", f.handlerAuthorizeOAuth)
	mux.HandleFunc("/vedsdk/Identity/Self", f.handlerIdentitySelf)
	mux.HandleFunc("/vedsdk/certificates/checkpolicy", f.handlerCertificatesCheckPolicy)
	mux.HandleFunc("/vedsdk/", f.handlerPing)
	mux.HandleFunc("/", f.handlerCatchAll)
	return f
}

func (o *Fake) handlerAuthorizeOAuth(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	o.log.Info("request", "uri", req.RequestURI)
	decoder := json.NewDecoder(req.Body)
	var in models.AuthorizeOAuthRequest
	if err := decoder.Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if in.Username != o.username || in.Password != o.password {
		// Mimics the behavior of TPP 20.4 and above. See:
		// https://github.com/jetstack/venafi-oauth-helper/issues/25#issuecomment-854037706
		http.Error(w, `{"error":"invalid_grant","error_description":"Username\/password combination not valid"}`,
			http.StatusBadRequest)
		return
	}
	o.WithRefreshToken(o.refreshToken + "x")
	o.WithAccessToken(o.accessToken + "x")
	out := models.AuthorizeOAuthResponse{
		AccessToken:  o.accessToken,
		Expires:      uint64(time.Now().UTC().Add(time.Hour).Unix()),
		RefreshToken: o.refreshToken,
		RefreshUntil: uint64(o.refreshTokenExpires.Unix()),
		Scope:        in.Scope,
		TokenType:    "Bearer",
		Identity:     "",
	}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(&out); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (o *Fake) handlerIdentitySelf(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	log := o.log.WithValues("uri", req.RequestURI).WithName("handlerIdentifySelf")
	log.V(1).Info("request")
	out := models.IdentityWebResponse{
		Identities: []*models.IdentityEntry{
			&models.IdentityEntry{
				Name: "Joe Bloggs",
			},
		},
	}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(&out); err != nil {
		log.Error(err, "While encoding response")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (o *Fake) handlerCertificatesCheckPolicy(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	log := o.log.WithValues("uri", req.RequestURI).WithName("handlerCertificatesCheckPolicy")
	log.V(1).Info("request")
	decoder := json.NewDecoder(req.Body)
	var in models.CheckPolicyRequest
	if err := decoder.Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := models.CheckPolicyResponse{}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(&out); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (o *Fake) handlerPing(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	o.log.Info("request", "uri", req.RequestURI)
	if req.URL.Path != "/vedsdk/" {
		panic(req)
	}
}

func (o *Fake) handlerCatchAll(w http.ResponseWriter, req *http.Request) {
	panic(req)
}

func logFromContext(ctx context.Context) logr.Logger {
	log, err := logr.FromContext(ctx)
	if err != nil {
		panic(err)
	}
	return log
}
