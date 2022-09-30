package fake

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/Venafi/vcert/v4/test/tpp/fake/models"
)

type application struct {
	clientID string
	scope    string
	users    sets.String
}

type user struct {
	username string
	password string
}

type token struct {
	token   string
	user    string
	expires time.Time
	scope   string
}

type state struct {
	sync.RWMutex
	users        map[string]user
	applications map[string]application
	grants       map[string]models.AuthorizeOAuthResponse
	accessTokens map[string]string
}

func (o *state) WithUser(username, password string) *state {
	o.Lock()
	defer o.Unlock()
	user := user{
		username: username,
		password: password,
	}
	o.users[user.username] = user
	return o
}

func (o *state) WithApplication(clientID, scope string, users ...string) *state {
	o.Lock()
	defer o.Unlock()
	application := application{
		clientID: clientID,
		scope:    scope,
		users:    sets.NewString(users...),
	}
	o.applications[application.clientID] = application
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
	o.accessTokens[grant.AccessToken] = grant.RefreshToken
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
	delete(o.accessTokens, grant.AccessToken)
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
	o.accessTokens[grant.AccessToken] = grant.RefreshToken
	return
}

func (o *state) LookupAccessToken(accessToken string) (grant models.AuthorizeOAuthResponse, found bool) {
	o.Lock()
	defer o.Unlock()
	refreshToken, found := o.accessTokens[accessToken]
	if !found {
		return
	}
	grant, found = o.grants[refreshToken]
	if !found {
		delete(o.accessTokens, accessToken)
	}
	// TODO(wallrj): Check for expired tokens
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
			grants:       map[string]models.AuthorizeOAuthResponse{},
			accessTokens: map[string]string{},
			users:        map[string]user{},
			applications: map[string]application{},
		},
		Server: ts,
	}
	mux.HandleFunc("/vedauth/authorize/oauth", f.handlerAuthorizeOAuth)
	mux.HandleFunc("/vedauth/authorize/token", f.handlerAuthorizeToken)
	mux.HandleFunc("/vedsdk/Identity/Self", f.checkBearerToken(f.handlerIdentitySelf))
	mux.HandleFunc("/vedsdk/certificates/checkpolicy", f.checkBearerToken(f.handlerCertificatesCheckPolicy))
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
	user, found := o.users[in.Username]
	if !found || in.Password != user.password {
		// Mimics the behavior of TPP 20.4 and above. See:
		// https://github.com/jetstack/venafi-oauth-helper/issues/25#issuecomment-854037706
		http.Error(w, `{"error":"invalid_grant","error_description":"Username\/password combination not valid"}`,
			http.StatusBadRequest)
		return
	}
	application, found := o.applications[in.ClientID]
	if !found {
		http.Error(w, `{"error":"invalid_grant","error_description":"Unknown client-id"}`,
			http.StatusBadRequest)
		return
	}

	if !application.users.Has(in.Username) {
		http.Error(w, `{"error":"invalid_grant","error_description":"Unknown client-id"}`,
			http.StatusBadRequest)
		return
	}

	// TODO(wallrj): Check that requested scope is a subset of the application scope
	// if in.Scope != application.scope {
	// 	http.Error(w, `{"error":"invalid_grant","error_description":"scope mismatch"}`,
	// 		http.StatusBadRequest)
	// 	return
	// }

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

	_, found = o.applications[in.ClientID]
	if !found {
		http.Error(w, `{"error":"invalid_grant","error_description":"Unknown client-id"}`,
			http.StatusBadRequest)
		return
	}

	encoder := json.NewEncoder(w)
	if err := encoder.Encode(&grant); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (o *Fake) checkBearerToken(wrapped http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		authHeader := req.Header.Get("Authorization")
		authParts := strings.Split(authHeader, " ")
		accessToken := authParts[1]
		_, found := o.LookupAccessToken(accessToken)
		if !found {
			http.Error(w, `{}`, http.StatusUnauthorized)
			return
		}
		wrapped(w, req)
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
