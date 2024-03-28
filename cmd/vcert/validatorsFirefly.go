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
		deviceURLPresent := flags.deviceURL != "" || getPropertyFromEnvironment(vcertDeviceURL) != ""

		credentialsFlowPresent := clientSecretPresent && clientIDPresent
		passwordFlowPresent := userPresent && passwordPresent && clientIDPresent
		deviceFlowPresent := deviceURLPresent && clientIDPresent

		if !urlPresent {
			return fmt.Errorf("missing URL for authentication. Set the URL using --url (-u) flag")
		}

		if !clientIDPresent {
			return fmt.Errorf("missing client id for authentication. Set the client-id using --client-id flag")
		}

		if userPresent && flags.noPrompt && !passwordPresent {
			return fmt.Errorf("missing password for password flow grant. Set the password using the --password flag")
		}

		advice := "Use only one of --client-id/--client-secret/--client-id, --username/--password/--client-id or --device-url/--client-id"
		if !credentialsFlowPresent && !passwordFlowPresent && !deviceFlowPresent {
			return fmt.Errorf("missing flags for Venafi Firefly authentication. %s", advice)
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
