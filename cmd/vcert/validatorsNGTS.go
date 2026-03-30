package main

import "fmt"

func validateConnectionFlagsNGTS(commandName string) error {
	//sshgetconfig command
	//For now this is not supported by Palo Alto Networks Next-Generation Trust Security (NGTS), but when (if) it does, it is going to be an unauthenticated endpoint, just like CyberArk Certificate Manager, Self-Hosted
	if commandName == commandSshGetConfigName {
		return nil
	}

	//getcred command
	if commandName == commandGetCredName {
		tokenURLPresent := flags.tokenURL != "" || getPropertyFromEnvironment(vCertTokenURL) != ""
		clientIDPresent := flags.clientId != "" || getPropertyFromEnvironment(vcertClientID) != ""
		clientSecretPresent := flags.clientSecret != "" || getPropertyFromEnvironment(vcertClientSecret) != ""
		scopePresent := flags.scope != "" || getPropertyFromEnvironment(vcertScope) != ""

		if !tokenURLPresent {
			return fmt.Errorf("missing token URL for service account authentication. Set the token URL using --token-url flag")
		}

		if !clientIDPresent {
			return fmt.Errorf("missing client ID for service account authentication. Set the client ID using --client-id flag")
		}

		if !clientSecretPresent {
			return fmt.Errorf("missing client secret for service account authentication. Set the client secret using --client-secret flag")
		}

		if !scopePresent {
			return fmt.Errorf("missing scope for service account authentication. Set the scope using --scope flag")
		}

		return nil
	}

	//Any other command
	tokenPresent := flags.token != "" || getPropertyFromEnvironment(vCertToken) != ""
	advice := "Use --token (-t)"
	if !tokenPresent {
		return fmt.Errorf("missing flags for Palo Alto Networks Next-Generation Trust Security (NGTS) authentication. %s", advice)
	}

	return nil
}
