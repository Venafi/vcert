package main

import "fmt"

func validateConnectionFlagsFirefly(commandName string) error {
	//sshgetconfig command
	//This is not supported for CyberArk Workload Identity Manager as of now, but when (if) it does, it is going to be an unauthenticated endpoint, just like CyberArk Certificate Manager, Self-Hosted
	if commandName == commandSshGetConfigName {
		return nil
	}

	urlPresent := flags.url != "" || getPropertyFromEnvironment(vCertURL) != ""

	//getcred command
	if commandName == commandGetCredName {
		clientSecretPresent := flags.clientSecret != "" || getPropertyFromEnvironment(vcertClientSecret) != ""
		clientIDPresent := flags.clientId != "" || getPropertyFromEnvironment(vcertClientID) != ""
		userPresent := flags.userName != "" || getPropertyFromEnvironment(vcertUser) != ""
		// Check if noPrompt is false. If False, it means VCert will request the password from user on CLI
		passwordPresent := flags.password != "" || getPropertyFromEnvironment(vcertPassword) != "" || !flags.noPrompt
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

		if userPresent && !passwordPresent {
			return fmt.Errorf("missing password for password flow grant. Set the password using the --password flag or remove --no-prompt flag")
		}

		advice := "Use only one of --client-id/--client-secret/--client-id, --username/--password/--client-id or --device-url/--client-id"
		if !credentialsFlowPresent && !passwordFlowPresent && !deviceFlowPresent {
			return fmt.Errorf("missing flags for CyberArk Workload Identity Manager authentication. %s", advice)
		}

		return nil
	}

	//any other command
	tokenPresent := flags.token != "" || getPropertyFromEnvironment(vCertToken) != ""

	if !urlPresent {
		return fmt.Errorf("missing URL to CyberArk Workload Identity Manager server. Set the URL using --url (-u) flag")
	}

	if !tokenPresent {
		return fmt.Errorf("an access token is required for authentication to CyberArk Workload Identity Manager. Set the access token using --token (-t) flag")
	}

	return nil
}
