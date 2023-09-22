package firefly

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDevAuthStatus_String(t *testing.T) {
	t.Run("Unknown", func(t *testing.T) {
		assert.Equal(t, "unknown", Unknown.String())
	})
	t.Run("AuthorizationPending", func(t *testing.T) {
		assert.Equal(t, "authorization_pending", AuthorizationPending.String())
	})
	t.Run("SlowDown", func(t *testing.T) {
		assert.Equal(t, "slow_down", SlowDown.String())
	})
	t.Run("AccessDenied", func(t *testing.T) {
		assert.Equal(t, "access_denied", AccessDenied.String())
	})
	t.Run("ExpiredToken", func(t *testing.T) {
		assert.Equal(t, "expired_token", ExpiredToken.String())
	})
}

func TestGetDevAuthStatusFromError(t *testing.T) {
	t.Run("Unknown_given_no_responseError", func(t *testing.T) {
		assert.Equal(t, Unknown, GetDevAuthStatusFromError(fmt.Errorf("no responseError")))
	})
	t.Run("Unknown", func(t *testing.T) {
		assert.Equal(t, Unknown, GetDevAuthStatusFromError(&responseError{"whatever", "error description"}))
	})
	t.Run("AuthorizationPending", func(t *testing.T) {
		assert.Equal(t, AuthorizationPending, GetDevAuthStatusFromError(&responseError{"authorization_pending", "error description"}))
	})
	t.Run("SlowDown", func(t *testing.T) {
		assert.Equal(t, SlowDown, GetDevAuthStatusFromError(&responseError{"slow_down", "error description"}))
	})
	t.Run("AccessDenied", func(t *testing.T) {
		assert.Equal(t, AccessDenied, GetDevAuthStatusFromError(&responseError{"access_denied", "error description"}))
	})
	t.Run("ExpiredToken", func(t *testing.T) {
		assert.Equal(t, ExpiredToken, GetDevAuthStatusFromError(&responseError{"expired_token", "error description"}))
	})
}

func TestGetDevAuthStatus(t *testing.T) {
	t.Run("Unknown", func(t *testing.T) {
		assert.Equal(t, Unknown, GetDevAuthStatus("Unknown"))
	})
	t.Run("AuthorizationPending", func(t *testing.T) {
		assert.Equal(t, AuthorizationPending, GetDevAuthStatus("Authorization_Pending"))
	})
	t.Run("SlowDown", func(t *testing.T) {
		assert.Equal(t, SlowDown, GetDevAuthStatus("Slow_Down"))
	})
	t.Run("AccessDenied", func(t *testing.T) {
		assert.Equal(t, AccessDenied, GetDevAuthStatus("Access_Denied"))
	})
	t.Run("ExpiredToken", func(t *testing.T) {
		assert.Equal(t, ExpiredToken, GetDevAuthStatus("Expired_Token"))
	})
}
