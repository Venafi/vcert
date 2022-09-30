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
	"github.com/google/uuid"
)

type state struct {
	sync.RWMutex
	username string
	password string
	grants   map[string]models.AuthorizeOAuthResponse
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

func (o *state) NewGrant(scope string) models.AuthorizeOAuthResponse {
	o.Lock()
	defer o.Unlock()
	grant := models.AuthorizeOAuthResponse{
		AccessToken:  uuid.Must(uuid.NewRandom()).String(),
		Expires:      uint64(time.Now().UTC().Add(time.Hour).Unix()),
		RefreshToken: uuid.Must(uuid.NewRandom()).String(),
		RefreshUntil: uint64(time.Now().Add(24 * time.Hour).Unix()),
		Scope:        scope,
		TokenType:    "Bearer",
		Identity:     "",
	}
	o.grants[grant.RefreshToken] = grant
	return grant
}

func (o *state) RefreshGrant(refreshToken string) (grant models.AuthorizeOAuthResponse, found bool) {
	o.Lock()
	defer o.Unlock()
	grant, found = o.grants[refreshToken]
	if !found {
		return
	}
	delete(o.grants, refreshToken)
	grant = models.AuthorizeOAuthResponse{
		AccessToken:  uuid.Must(uuid.NewRandom()).String(),
		Expires:      uint64(time.Now().UTC().Add(time.Hour).Unix()),
		RefreshToken: uuid.Must(uuid.NewRandom()).String(),
		// TPP does absolute refresh-token expiry rather than a sliding expiry.
		// The expiry time is the same everytime you rotate the refresh-token.
		RefreshUntil: grant.RefreshUntil,
		Scope:        grant.Scope,
		TokenType:    "Bearer",
		Identity:     "",
	}
	o.grants[grant.RefreshToken] = grant
	return
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
		log: log,
		state: &state{
			grants: map[string]models.AuthorizeOAuthResponse{},
		},
		Server: ts,
	}
	mux.HandleFunc("/vedauth/authorize/oauth", f.handlerAuthorizeOAuth)
	mux.HandleFunc("/vedauth/authorize/token", f.handlerAuthorizeToken)
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
	grant := o.NewGrant(in.Scope)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(&grant); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (o *Fake) handlerAuthorizeToken(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	log := o.log.WithValues("uri", req.RequestURI).WithName("handlerAuthorizeToken")
	log.V(1).Info("request")
	decoder := json.NewDecoder(req.Body)
	var in models.RefreshOAuthRequest
	if err := decoder.Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	grant, found := o.RefreshGrant(in.RefreshToken)
	if !found {
		http.Error(w, "bad token", http.StatusBadRequest)
		return
	}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(&grant); err != nil {
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
