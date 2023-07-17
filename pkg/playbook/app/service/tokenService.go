package service

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/parser"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/vcertutil"
)

// ValidateTPPCredentials checks that the TPP credentials are not expired.
//
// If expired, it will try to get a new token pair using the refreshToken.
//
// If the refreshing is successful it will save the new token pair in the playbook file.
func ValidateTPPCredentials(playbook *domain.Playbook) error {
	//Validate TPP tokens
	if playbook.Config.Connection.Credentials.AccessToken != "" {
		isValid, err := vcertutil.IsValidAccessToken(playbook.Config)
		// Return any error besides 401 Unauthorized - need to properly handle errors unlrelated to the state of the token (connectivity)
		if err != nil && err.Error() != "failed to verify token. Message: 401 Unauthorized" {
			return err
		}
		if isValid {
			return nil
		}
	}

	zap.L().Info("access token is invalid, missing, or expired")
	if playbook.Config.Connection.Credentials.RefreshToken == "" && playbook.Config.Connection.Credentials.PKCS12 == "" {
		return fmt.Errorf("access token no longer valid and no authorization methods specified - cannot get a new access token")
	}

	zap.L().Info("using refresh token")

	// Read the playbook first, to make sure we can, before refreshing the tokens
	// and blowing things up!
	pbData, err := parser.ReadPlaybookRaw(playbook.Location)
	if err != nil {
		return err
	}

	accessToken, refreshToken, err := vcertutil.RefreshTPPTokens(playbook.Config)
	if err != nil {
		zap.L().Error("failed to refresh TPP Tokens")
		return err
	}
	zap.L().Info("successfully retrieved new refresh token")

	playbook.Config.Connection.Credentials.AccessToken = accessToken
	playbook.Config.Connection.Credentials.RefreshToken = refreshToken

	err = replaceTokensInFile(pbData, accessToken, refreshToken)
	if err != nil {
		return err
	}

	err = parser.WritePlaybook(pbData, playbook.Location)
	if err != nil {
		zap.L().Error("failed to serialize new tokens to playbook file")
		return err
	}

	return nil
}

func replaceTokensInFile(playbook map[string]interface{}, accessToken string, refreshToken string) error {

	if playbook == nil {
		return fmt.Errorf("playbook data is nil")
	}
	cfg, found := playbook["config"]
	if !found {
		return fmt.Errorf("no config found in Playbook data")
	}

	conn, found := cfg.(map[string]interface{})["connection"]
	if !found {
		return fmt.Errorf("no connection found in Playbook data")
	}

	creds, found := conn.(map[string]interface{})["credentials"]
	if !found {
		return fmt.Errorf("no credentials found in Playbook data")
	}

	credsMap := creds.(map[string]interface{})
	credsMap["accessToken"] = accessToken
	credsMap["refreshToken"] = refreshToken

	return nil
}
