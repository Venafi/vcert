package vcertutil

import (
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"
)

// TestGeneratePasswordMeetsPasswordRule checks the rule CM SaaS applies to key passwords (HTTP 400, code 12301 when
// it is not met): at least 12 characters, a digit, an uppercase letter and one of its special characters.
func TestGeneratePasswordMeetsPasswordRule(t *testing.T) {
	const specialCharacters = "@%+^'!#$?:,(){}[]~.-_`"
	for i := 0; i < 100; i++ {
		password := GeneratePassword()
		require.GreaterOrEqual(t, len(password), 12, password)
		require.True(t, strings.IndexFunc(password, unicode.IsDigit) >= 0, "no digit in %q", password)
		require.True(t, strings.IndexFunc(password, unicode.IsUpper) >= 0, "no uppercase letter in %q", password)
		require.True(t, strings.ContainsAny(password, specialCharacters), "no special character in %q", password)
	}
}
