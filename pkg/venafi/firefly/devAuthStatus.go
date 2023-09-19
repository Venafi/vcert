package firefly

import (
	"errors"
	"strings"
)

type DevAuthStatus int

const (
	Unknown DevAuthStatus = iota
	AuthorizationPending
	SlowDown
	AccessDenied
	ExpiredToken

	strUnknown      = "unknown"
	strAuthPending  = "authorization_pending"
	strSlowDown     = "slow_down"
	strAccessDenied = "access_denied"
	strExpiredToken = "expired_token"
)

func (das DevAuthStatus) String() string {
	switch das {
	case AuthorizationPending:
		return strAuthPending
	case SlowDown:
		return strSlowDown
	case AccessDenied:
		return strAccessDenied
	case ExpiredToken:
		return strExpiredToken
	default:
		return strUnknown
	}
}

func GetDevAuthStatusFromError(err error) DevAuthStatus {
	var respError *responseError
	if errors.As(err, &respError) {
		return GetDevAuthStatus(respError.ErrorKey)
	}
	return Unknown
}

func GetDevAuthStatus(devAuthStatus string) DevAuthStatus {
	switch strings.ToLower(devAuthStatus) {
	case strAuthPending:
		return AuthorizationPending
	case strSlowDown:
		return SlowDown
	case strAccessDenied:
		return AccessDenied
	case strExpiredToken:
		return ExpiredToken
	default:
		return Unknown
	}
}
