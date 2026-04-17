package ngts

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Venafi/vcert/v5/pkg/verror"
)

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

type AccessTokenClaims struct {
	Exp int64 `json:"exp"`
}

// AccessTokenErrorResponse represents an OAuth2 error response from the token endpoint
// Follows RFC 6749 Section 5.2: https://tools.ietf.org/html/rfc6749#section-5.2
type AccessTokenErrorResponse struct {
	ErrorCode        string `json:"error"`               // OAuth2 error code (e.g., "invalid_client", "invalid_grant")
	ErrorDescription string `json:"error_description"`   // Human-readable error description
	ErrorURI         string `json:"error_uri,omitempty"` // URI with more information about the error
	StatusCode       int    `json:"-"`                   // HTTP status code (not from JSON response)
	Status           string `json:"-"`                   // HTTP status text (e.g., "401 Unauthorized")
}

// Error implements the error interface
func (e *AccessTokenErrorResponse) Error() string {
	if e.ErrorDescription != "" {
		return fmt.Sprintf("OAuth token error (status %d): %s - %s", e.StatusCode, e.ErrorCode, e.ErrorDescription)
	}
	if e.ErrorCode != "" {
		return fmt.Sprintf("OAuth token error (status %d): %s", e.StatusCode, e.ErrorCode)
	}
	return fmt.Sprintf("OAuth token error (status %d): %s", e.StatusCode, e.Status)
}

func parseAccessTokenResponse(expectedStatusCode int, statusCode int, httpStatus string, body []byte) (*AccessTokenResponse, error) {
	if expectedStatusCode == statusCode {
		return parseAccessTokenData(body)
	}

	// Try parsing as OAuth2 standard error response first
	var oauthErr AccessTokenErrorResponse
	err := json.Unmarshal(body, &oauthErr)
	if err == nil && oauthErr.ErrorCode != "" {
		// Successfully parsed OAuth2 error format
		oauthErr.StatusCode = statusCode
		oauthErr.Status = httpStatus
		return nil, &oauthErr
	}

	// Fall back to generic error parsing (for errors that won't conform to OAuth2 error format)
	errors, err := parseResponseErrors(body)
	if err != nil {
		// In case error parsing fails, return a generic AccessTokenErrorResponse
		bodyText := strings.TrimSpace(string(body))
		return nil, &AccessTokenErrorResponse{
			ErrorCode:        "unknown_error",
			ErrorDescription: bodyText,
			StatusCode:       statusCode,
			Status:           httpStatus,
		}
	}

	// Build error description from parsed errors
	var errorDesc string
	for _, e := range errors {
		errorDesc += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
	}
	return nil, &AccessTokenErrorResponse{
		ErrorCode:        "server_error",
		ErrorDescription: strings.TrimSpace(errorDesc),
		StatusCode:       statusCode,
		Status:           httpStatus,
	}
}

func parseAccessTokenData(data []byte) (*AccessTokenResponse, error) {
	var response AccessTokenResponse
	err := json.Unmarshal(data, &response)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", verror.ServerError, err)
	}

	return &response, nil
}
