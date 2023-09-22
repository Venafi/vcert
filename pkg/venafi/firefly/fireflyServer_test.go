package firefly

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
)

const (
	TestingPolicyName        = "myPolicy"
	TestingFailingPolicyName = "failingPolicy" // used to return a corrupted certificate
)

func newFireflyMockServer() *FireflyMockServer {
	certReqPath := "/v1/certificaterequest"
	certSignReqPath := "/v1/certificatesigningrequest"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//getting the AccessToken
		accessToken := getAccessToken(r)
		if accessToken == "" {
			writeError(w, http.StatusBadRequest, "no-accessToken", "the access token was not provided")
			return
		}

		//validating the AccessToken
		if accessToken != TestingAccessToken {
			writeError(w, http.StatusUnauthorized, "no-authorized", "the access token is not valid")
			return
		}

		switch strings.TrimSpace(r.URL.Path) {
		case certReqPath:
			processCertificateRequest(w, r)
		case certSignReqPath:
			processCertificateSigningRequest(w, r)
		default:
			http.NotFoundHandler().ServeHTTP(w, r)
		}
	}))
	//creating and returning the Firefly server
	return &FireflyMockServer{
		server:          server,
		serverURL:       server.URL,
		certReqPath:     certReqPath,
		certSignReqPath: certSignReqPath,
	}
}

type FireflyMockServer struct {
	server          *httptest.Server
	serverURL       string
	certReqPath     string
	certSignReqPath string
}

func getAccessToken(r *http.Request) string {
	//getting the BearerToken
	bearerToken := r.Header.Get("Authorization")
	if bearerToken == "" {
		return ""
	}

	accessToken, found := strings.CutPrefix(bearerToken, "Bearer ")
	if !found {
		return ""
	}
	return accessToken
}

func processCertificateRequest(w http.ResponseWriter, r *http.Request) {
	var certReq certificateRequest

	if r.Method != http.MethodPost {
		http.NotFoundHandler().ServeHTTP(w, r)
		return
	}

	// Try to decode the request body into the struct. If there is an error,
	// respond to the client with the error message and a 400 status code.
	err := json.NewDecoder(r.Body).Decode(&certReq)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	//validating that the subject was provided given is required
	if reflect.DeepEqual(certReq.Subject, Subject{}) {
		writeError(w, http.StatusBadRequest, "no-subject", "the subject was not provided")
		return
	}

	//validating that the policy name was provided given is required
	if certReq.PolicyName == "" {
		writeError(w, http.StatusBadRequest, "no-policyName", "the policy name was not provided")
		return
	}

	if certReq.PolicyName != TestingPolicyName && certReq.PolicyName != TestingFailingPolicyName {
		writeError(w, http.StatusBadRequest, "invalid-policyName", "the policy name is not valid")
		return
	}

	var certChain = cert_test
	if certReq.PolicyName == TestingFailingPolicyName {
		certChain = cert_test_corrupted
	}

	//Headers must be set before the status and the body are written to the response.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	certificateRequestResponse := certificateRequestResponse{
		CertificateChain: certChain,
		PrivateKey:       pk_test,
	}

	jsonResp, err := json.Marshal(certificateRequestResponse)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(jsonResp)
}

func processCertificateSigningRequest(w http.ResponseWriter, r *http.Request) {
	var certReq certificateRequest

	if r.Method != http.MethodPost {
		http.NotFoundHandler().ServeHTTP(w, r)
		return
	}

	// Try to decode the request body into the struct. If there is an error,
	// respond to the client with the error message and a 400 status code.
	err := json.NewDecoder(r.Body).Decode(&certReq)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	//validating that the CSR was provided given is required
	if certReq.CSR == "" {
		writeError(w, http.StatusBadRequest, "no-csr", "the CSR was not provided")
		return
	}

	//validating that the policy name was provided given is required
	if certReq.PolicyName == "" {
		writeError(w, http.StatusBadRequest, "no-policyName", "the policy name was not provided")
		return
	}

	if certReq.PolicyName != TestingPolicyName && certReq.PolicyName != TestingFailingPolicyName {
		writeError(w, http.StatusBadRequest, "invalid-policyName", "the policy name is not valid")
		return
	}

	var certChain = cert_test
	if certReq.PolicyName == TestingFailingPolicyName {
		certChain = cert_test_corrupted
	}

	//Headers must be set before the status and the body are written to the response.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	certificateRequestResponse := certificateRequestResponse{
		CertificateChain: certChain,
	}

	jsonResp, err := json.Marshal(certificateRequestResponse)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(jsonResp)
}
