package cloud

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Venafi/vcert/v5/pkg/verror"
)

type TLSPCAccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

func parseAccessTokenResponse(expectedStatusCode int, statusCode int, httpStatus string, body []byte) (*TLSPCAccessTokenResponse, error) {
	if expectedStatusCode == statusCode {
		return parseAccessTokenData(body)
	}

	errors, err := parseResponseErrors(body)
	if err != nil {
		// Parsing the error failed, return the original error
		bodyText := strings.TrimSpace(string(body))
		if bodyText == "" {
			return nil, fmt.Errorf("%w: %s", verror.ServerError, httpStatus)
		}
		return nil, fmt.Errorf("%w: %s, %s", verror.ServerError, httpStatus, bodyText)
	}
	respError := fmt.Sprintf("unexpected status code on CyberArk Certificate Manager, SaaS Authentication. Status: %s\n", httpStatus)
	for _, e := range errors {
		respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
	}
	return nil, fmt.Errorf("%w: %v", verror.ServerError, respError)
}

func parseAccessTokenData(data []byte) (*TLSPCAccessTokenResponse, error) {
	var response TLSPCAccessTokenResponse
	err := json.Unmarshal(data, &response)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", verror.ServerError, err)
	}

	return &response, nil
}
