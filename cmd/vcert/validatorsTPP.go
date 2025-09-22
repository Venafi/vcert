package main

import (
	"fmt"
)

func validateConnectionFlagsTPP(commandName string) error {
	tokenPresent := flags.token != "" || getPropertyFromEnvironment(vCertToken) != ""
	userPresent := flags.userName != "" || getPropertyFromEnvironment(vcertUser) != ""
	// Check if noPrompt is false. If False, it means VCert will request the password from user on CLI
	passwordPresent := flags.password != "" || getPropertyFromEnvironment(vcertPassword) != "" || !flags.noPrompt
	p12PasswordPresent := flags.clientP12PW != "" || !flags.noPrompt
	clientCertificatePresent := flags.clientP12 != "" && p12PasswordPresent
	userPasswordPresent := userPresent && passwordPresent
	urlPresent := flags.url != "" || getPropertyFromEnvironment(vCertURL) != ""

	if !urlPresent {
		return fmt.Errorf("missing URL for authentication. Set the url using -u flag")
	}

	// mutual TLS with TPP service
	if flags.clientP12 != "" && !p12PasswordPresent {
		return fmt.Errorf("missing password for client certificate authentication. Set the password using --p12-password flag or remove --no-prompt flag")
	}

	// Username/password combination
	if userPresent && !passwordPresent {
		return fmt.Errorf("missing password for username/password authentication. Set the password using --password flag or remove --no-prompt flag")
	}

	advice := "Use only one of --token (-t), --p12-file/--p12-password] or --username/--password"
	if !tokenPresent && !userPasswordPresent && !clientCertificatePresent {
		return fmt.Errorf("missing flags for CyberArk Certificate Manager, Self-Hosted authentication. %s", advice)
	}

	// Warning not valid when using user/password to obtain a token
	if userPasswordPresent && commandName != commandGetCredName {
		logf("Warning: username/password authentication is DEPRECATED, please use access token or client certificate instead")
	}

	return nil
}
