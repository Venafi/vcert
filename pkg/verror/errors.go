package verror

import "fmt"

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
