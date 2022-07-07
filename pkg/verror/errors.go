package verror

import (
	"encoding/json"
	"fmt"
)

var (
	VcertError                      = fmt.Errorf("vcert error")
	ServerError                     = fmt.Errorf("%w: server error", VcertError)
	ServerUnavailableError          = fmt.Errorf("%w: server unavailable", ServerError)
	ServerTemporaryUnavailableError = fmt.Errorf("%w: temporary", ServerUnavailableError)
	ServerBadDataResponce           = fmt.Errorf("%w: server returns 400 code. your request has problems", ServerError)
	UserDataError                   = fmt.Errorf("%w: your data contains problems", VcertError)
	PolicyValidationError           = fmt.Errorf("%w: policy doesn't match request", VcertError)
	CertificateCheckError           = fmt.Errorf("%w: request doesn't match certificate", UserDataError)
	AuthError                       = fmt.Errorf("%w: auth error", UserDataError)
	ZoneNotFoundError               = fmt.Errorf("%w: zone not found", UserDataError)
	ApplicationNotFoundError        = fmt.Errorf("%w: application not found", UserDataError)
)

//	Type definitions
//
// VCertError is the most generic VCert error of which all other errors are
// inherited, and it is based on the default golang error type
type VCertError                                             struct{ error }

type VCertPolicyError                                       struct{ VCertError }
type VCertPolicyUnspecifiedPolicyError                      struct{ VCertPolicyError }
type VCertPolicyUnsupportedFileError                        struct{ VCertPolicyError }
type VCertPolicyAttributeError                              struct{ VCertPolicyError }
type VCertPolicyUnaryAttributeError                         struct{ VCertPolicyAttributeError; Attribute string }
type VCertPolicyCountryAttributeError                       struct{ VCertPolicyAttributeError }
type VCertPolicyCountryDefaultAttributeError                struct{ VCertPolicyAttributeError }
type VCertPolicyUnmatchedAttributeError                     struct{ VCertPolicyAttributeError; Attribute string }
type VCertPolicyUnmatchedDefaultAttributeError              struct{ VCertPolicyAttributeError; Attribute string; AttributePlural string }
type VCertPolicyUnmatchedDefaultValueAttributeError         struct{ VCertPolicyAttributeError; Attribute string; Value           string }
type VCertPolicyUnmatchedDefaultAutoInstalledAttributeError struct{ VCertPolicyAttributeError }
type VCertPolicyIsNullError                                 struct{ VCertPolicyError }
type VCertPolicyKeyLengthValueError                         struct{ VCertPolicyError;          Value     string }
type VCertPolicyInvalidCAError                              struct{ VCertPolicyError }
type VCertPolicyUnsupportedKeyTypeError                     struct{ VCertPolicyError }

func (e VCertPolicyUnspecifiedPolicyError) Error() string {
	return fmt.Sprintf("policy specification is nil")
}

func (e VCertPolicyUnsupportedFileError) Error() string {
	return fmt.Sprintf("the specified file is not supported")
}

func (e VCertPolicyUnaryAttributeError) Error() string {
	return fmt.Sprintf("attribute %s has more than one value", e.Attribute)
}

func (e VCertPolicyCountryAttributeError) Error() string {
	return fmt.Sprintf("number of country's characters, doesn't match to two characters")
}

func (e VCertPolicyCountryDefaultAttributeError) Error() string {
	return fmt.Sprintf("number of default country's characters, doesn't match to two characters")
}

func (e VCertPolicyUnmatchedAttributeError) Error() string {
	return fmt.Sprintf("specified default %s doesn't match with the supported ones", e.Attribute)
}

func (e VCertPolicyUnmatchedDefaultAttributeError) Error() string {
	return fmt.Sprintf("policy default %s doesn't match with policy's %s value", e.Attribute, e.AttributePlural)
}

func (e VCertPolicyUnmatchedDefaultValueAttributeError) Error() string {
	return fmt.Sprintf("specified default %s value: %s  doesn't match with specified policy %s", e.Attribute, e.Value, e.Attribute)
}

func (e VCertPolicyUnsupportedKeyTypeError) Error() string {
	return fmt.Sprintf("specified default attribute keyType value is not supported on VaaS")
}

func (e VCertPolicyUnmatchedDefaultAutoInstalledAttributeError) Error() string {
	return fmt.Sprintf("default autoInstalled attribute value doesn't match with policy's autoInstalled attribute value")
}

func (e VCertPolicyIsNullError) Error() string {
	return fmt.Sprintf("policy is nul")
}

func (e VCertPolicyKeyLengthValueError) Error() string {
	return fmt.Sprintf("specified attribute key length value: %s is not supported on VaaS", e.Value)
}

func (e VCertPolicyInvalidCAError) Error() string {
	return fmt.Sprintf("certificate Authority is invalid, please provide a valid value with this structure: ca_type\\ca_account_key\\vendor_product_name")
}

type VCertLoadConfigError struct {
	VCertError
	Description error
}

func (e VCertLoadConfigError) Error() string {
	return fmt.Sprintf("failed to load config: %s", e.Description)
}

type VCertConnectorError struct {
	VCertError
	Status string
	Body   []byte
}

// VCertServerError is the error used when a non standard response is returned
// from the server.
type VCertServerError struct {
	VCertError
	Type        string `json:"error"`
	Description string `json:"error_description"`
}

// InvalidTokenError is used when the server responds with an `invalid_token`
// error.
type InvalidTokenError struct{ VCertServerError }

func (e VCertServerError) Error() string {
	// Generic server error
	return fmt.Sprintf("Server error: `%s` Error description: %s", e.Type, e.Description)
}

func (e InvalidTokenError) Error() string {
	// Don't display token
	return fmt.Sprintf("Invalid token provided.")
}
