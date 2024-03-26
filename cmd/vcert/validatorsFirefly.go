package main

import "fmt"

func validateConnectionFlagsFirefly(commandName string) error {
	//sshgetconfig command
	//This is not supported for Firefly as of now, but when (if) it does, it is going to be an unauthenticated endpoint, just like TPP
	if commandName == commandSshGetConfigName {
		return nil
	}

	urlPresent := flags.url != "" || getPropertyFromEnvironment(vCertURL) != ""

	//getcred command
	if commandName == commandGetCredName {
		clientSecretPresent := flags.clientSecret != "" || getPropertyFromEnvironment(vcertClientSecret) != ""
		clientIDPresent := flags.clientId != "" || getPropertyFromEnvironment(vcertClientID) != ""
		userPresent := flags.userName != "" || getPropertyFromEnvironment(vcertUser) != ""
		passwordPresent := flags.password != "" || getPropertyFromEnvironment(vcertPassword) != ""
		deviceFlowPresent := flags.deviceURL != "" || getPropertyFromEnvironment(vcertDeviceURL) != ""
		credentialsFlowPresent := clientSecretPresent && clientIDPresent
		passwordFlowPresent := userPresent && passwordPresent

		if !urlPresent {
			return fmt.Errorf("missing URL for authentication. Set the URL using --url (-u) flag")
		}

		advice := "Use only one of --client-id/--client-secret, --username/--password or --device-url"
		if deviceFlowPresent && credentialsFlowPresent ||
			deviceFlowPresent && passwordFlowPresent ||
			credentialsFlowPresent && passwordFlowPresent {
			return fmt.Errorf("multiple methods set for Firefly authentication. %s", advice)

		}

		if clientIDPresent && !clientSecretPresent {
			return fmt.Errorf("missing client-secret for client credentials flow grant. Set the secret using --client-secret flag")
		}

		if userPresent && flags.noPrompt && !passwordPresent {
			return fmt.Errorf("missing password for password flow grant. Set the password using the --password flag")
		}

		return nil
	}

	//any other command
	tokenPresent := flags.token != "" || getPropertyFromEnvironment(vCertToken) != ""

	if !urlPresent {
		return fmt.Errorf("missing URL to Firefly server. Set the URL using --url (-u) flag")
	}

	if !tokenPresent {
		return fmt.Errorf("an access token is required for authentication to Firefly. Set the access token using --token (-t) flag")
	}

	return nil
}
