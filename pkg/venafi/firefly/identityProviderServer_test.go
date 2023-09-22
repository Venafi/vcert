package firefly

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
)

const (
	TestingClientID              = "1234567890"
	TestingClientSecret          = "my_secret"
	TestingUserName              = "my_name"
	TestingUserPassword          = "my_password"
	TestingDeviceCode            = "my_device_code"
	TestingClientIDAuthPending   = "123"
	TestingDeviceAuthPending     = "device_code_pending"
	TestingClientIDSlowDown      = "456"
	TestingDeviceSlowDown        = "device_code_slow_down"
	TestingClientIDAccessDenied  = "789"
	TestingDeviceAccessDenied    = "device_code_access_denied"
	TestingClientIDExpiredToken  = "012"
	TestingDeviceExpiredToken    = "device_code_expired_token"
	TestingDeviceVerificationUri = "my_device_uri"
	TestingScope                 = "my_scope"
	TestingAudience              = "my_audience"
	TestingAccessToken           = "my_access_token"
)

var (
	authPendingCount = 0
	slowDownCount    = 0
)

func newIdentityProviderMockServer() *IdentityProviderMockServer {
	tokenPath := "/token"
	devicePath := "/device"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimSpace(r.URL.Path) {
		case tokenPath:
			processAccessTokenRequest(w, r)
		case devicePath:
			processDeviceCodeRequest(w, r)
		default:
			http.NotFoundHandler().ServeHTTP(w, r)
		}
	}))
	//creating and returning the idp server
	return &IdentityProviderMockServer{
		server:     server,
		idpURL:     server.URL,
		tokenPath:  tokenPath,
		devicePath: devicePath,
	}
}

type IdentityProviderMockServer struct {
	server     *httptest.Server
	idpURL     string
	tokenPath  string
	devicePath string
}

type AccessTokenRequest struct {
	grantType    string `json:"grant_type"`
	clientId     string `json:"client_id"`
	clientSecret string `json:"client_secret,omitempty"`
	username     string `json:"username,omitempty"`
	password     string `json:"password,omitempty"`
	deviceCode   string `json:"device_code"`
	scope        string `json:"scope"`
	audience     string `json:"audience,omitempty"`
}

type AccessTokenResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int32  `json:"expires_in"`
	Scope        string `json:"scope"`
}

func processAccessTokenRequest(w http.ResponseWriter, r *http.Request) {
	accessTokenRequest, err := parseAccessTokenRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	if !validateAccessTokenRequest(w, accessTokenRequest) {
		return
	}

	//Headers must be set before the status and the body are written to the response.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	accessTokenResponse := AccessTokenResponse{
		TokenType:    "Bearer",
		AccessToken:  TestingAccessToken,
		RefreshToken: "",
		ExpiresIn:    120, //seconds
		Scope:        TestingScope,
	}

	jsonResp, err := json.Marshal(accessTokenResponse)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(jsonResp)
}

// validateAccessTokenRequest returns true if the request is valid, else return false
func validateAccessTokenRequest(w http.ResponseWriter, accessTokenRequest AccessTokenRequest) bool {
	if accessTokenRequest.clientId == "" {
		writeError(w, http.StatusBadRequest, "Status Bad Request", "The client_id is missing")
		return false
	}

	switch accessTokenRequest.grantType {
	case "client_credentials":
		if accessTokenRequest.clientId != TestingClientID {
			writeError(w, http.StatusUnauthorized, "Status Unauthorized Request", "The client_id is not valid")
			return false
		}

		if accessTokenRequest.clientSecret == "" {
			writeError(w, http.StatusBadRequest, "Status Bad Request", "The client_secret is missing")
			return false
		}

		if accessTokenRequest.clientSecret != TestingClientSecret {
			writeError(w, http.StatusUnauthorized, "Status Unauthorized Request", "The client_secret is not valid")
			return false
		}

		if accessTokenRequest.scope == "" {
			writeError(w, http.StatusBadRequest, "Status Bad Request", "The scope is missing")
			return false
		}

		if accessTokenRequest.scope != TestingScope {
			writeError(w, http.StatusUnauthorized, "Status Unauthorized Request", "The scope is not valid")
			return false
		}
	case "password":
		if accessTokenRequest.clientId != TestingClientID {
			writeError(w, http.StatusUnauthorized, "Status Unauthorized Request", "The client_id is not valid")
			return false
		}

		if accessTokenRequest.username == "" {
			writeError(w, http.StatusBadRequest, "Status Bad Request", "The username is missing")
			return false
		}

		if accessTokenRequest.username != TestingUserName {
			writeError(w, http.StatusUnauthorized, "Status Unauthorized Request", "The username is not valid")
			return false
		}

		if accessTokenRequest.password == "" {
			writeError(w, http.StatusBadRequest, "Status Bad Request", "The password is missing")
			return false
		}

		if accessTokenRequest.password != TestingUserPassword {
			writeError(w, http.StatusUnauthorized, "Status Unauthorized Request", "The password is not valid")
			return false
		}

		if accessTokenRequest.scope == "" {
			writeError(w, http.StatusBadRequest, "Status Bad Request", "The scope is missing")
			return false
		}

		if accessTokenRequest.scope != TestingScope {
			writeError(w, http.StatusUnauthorized, "Status Unauthorized Request", "The scope is not valid")
			return false
		}
	case "urn:ietf:params:oauth:grant-type:device_code":
		if accessTokenRequest.deviceCode == "" {
			writeError(w, http.StatusBadRequest, "Status Bad Request", "The device_code is missing")
			return false
		}

		if accessTokenRequest.clientId == TestingClientID {
			if accessTokenRequest.deviceCode != TestingDeviceCode {
				writeError(w, http.StatusUnauthorized, "Status Unauthorized Request", "The device code is not valid")
				return false
			}
		}

		if accessTokenRequest.clientId == TestingClientIDAuthPending {
			authPendingCount++
			if accessTokenRequest.deviceCode == TestingDeviceAuthPending {
				if authPendingCount < 3 {
					writeError(w, http.StatusTooEarly, "authorization_pending", "")
				} else {
					//reset the authPendingCount
					authPendingCount = 0
					return true
				}
			} else {
				writeError(w, http.StatusUnauthorized, "Status Unauthorized Request", "The device code is not valid")
			}

			return false
		}

		if accessTokenRequest.clientId == TestingClientIDSlowDown {
			slowDownCount++
			if accessTokenRequest.deviceCode == TestingDeviceSlowDown {
				if slowDownCount < 2 {
					writeError(w, http.StatusTooEarly, "slow_down", "")
				} else {
					//reset the slowDownCount
					slowDownCount = 0
					return true
				}
			} else {
				writeError(w, http.StatusUnauthorized, "Status Unauthorized Request", "The device code is not valid")
			}
			return false
		}

		if accessTokenRequest.clientId == TestingClientIDAccessDenied {
			if accessTokenRequest.deviceCode == TestingDeviceAccessDenied {
				writeError(w, http.StatusUnauthorized, "access_denied", "")
			} else {
				writeError(w, http.StatusUnauthorized, "Status Unauthorized Request", "The device code is not valid")
			}
			return false
		}

		if accessTokenRequest.clientId == TestingClientIDExpiredToken {
			if accessTokenRequest.deviceCode == TestingDeviceExpiredToken {
				writeError(w, http.StatusUnauthorized, "expired_token", "")
			} else {
				writeError(w, http.StatusUnauthorized, "Status Unauthorized Request", "The device code is not valid")
			}
			return false
		}
	}

	if accessTokenRequest.audience != "" && accessTokenRequest.audience != TestingAudience {
		writeError(w, http.StatusUnauthorized, "Status Unauthorized Request", "The audience is not valid")
		return false
	}

	return true
}

func parseAccessTokenRequest(r *http.Request) (accessTokenRequest AccessTokenRequest, err error) {
	err = r.ParseForm()
	if err != nil {
		return
	}

	accessTokenRequest = AccessTokenRequest{}

	for key, value := range r.Form {
		switch key {
		case "grant_type":
			accessTokenRequest.grantType = value[0]
		case "client_id":
			accessTokenRequest.clientId = value[0]
		case "client_secret":
			accessTokenRequest.clientSecret = value[0]
		case "username":
			accessTokenRequest.username = value[0]
		case "password":
			accessTokenRequest.password = value[0]
		case "device_code":
			accessTokenRequest.deviceCode = value[0]
		case "scope":
			accessTokenRequest.scope = value[0]
		case "audience":
			accessTokenRequest.audience = value[0]
		}
	}

	//if the client_id was not as a query parameter
	if accessTokenRequest.clientId == "" {
		if username, password, ok := r.BasicAuth(); ok {
			accessTokenRequest.clientId = username
			accessTokenRequest.clientSecret = password
		}
	}

	return
}

func processDeviceCodeRequest(w http.ResponseWriter, r *http.Request) {
	var clientId, scope, audience, deviceCode string

	err := r.ParseForm()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	// getting the clientID, the scope and the audience
	for key, value := range r.Form {
		switch key {
		case "client_id":
			clientId = value[0]
		case "scope":
			scope = value[0]
		case "audience":
			audience = value[0]
		}
	}

	//if the client_id was not as a query parameter
	if clientId == "" {
		if username, _, ok := r.BasicAuth(); ok {
			clientId = username
		}
	}

	//validating the parameters gotten
	if clientId == "" {
		writeError(w, http.StatusBadRequest, "Status Bad Request", "The client_id is missing")
		return
	}

	if scope != "" && scope != TestingScope {
		writeError(w, http.StatusUnauthorized, "Status Unauthorized Request", "The scope is not valid")
		return
	}

	if audience != "" && audience != TestingAudience {
		writeError(w, http.StatusUnauthorized, "Status Unauthorized Request", "The audience is not valid")
		return
	}

	//Determining the deviceCode to send
	switch clientId {
	case TestingClientID:
		deviceCode = TestingDeviceCode
	case TestingClientIDAuthPending:
		deviceCode = TestingDeviceAuthPending
	case TestingClientIDSlowDown:
		deviceCode = TestingDeviceSlowDown
	case TestingClientIDAccessDenied:
		deviceCode = TestingDeviceAccessDenied
	case TestingClientIDExpiredToken:
		deviceCode = TestingDeviceExpiredToken
	}

	//Headers must be set before the status and the body are written to the response.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	deviceCred := DeviceCred{
		DeviceCode:      deviceCode,
		UserCode:        "1234",
		VerificationURL: "",
		VerificationURI: TestingDeviceVerificationUri,
		Interval:        3,
		ExpiresIn:       15,
	}

	jsonResp, err := json.Marshal(deviceCred)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(jsonResp)

	return
}
