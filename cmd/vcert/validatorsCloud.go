package main

import "fmt"

func validateConnectionFlagsCloud(commandName string) error {
	//sshgetconfig command
	//For now this is not supported by CyberArk Certificate Manager, SaaS, but when (if) it does, it is going to be an unauthenticated endpoint, just like CyberArk Certificate Manager, Self-Hosted
	if commandName == commandSshGetConfigName {
		return nil
	}

	//getcred command
	if commandName == commandGetCredName {
		tokenURLPresent := flags.tokenURL != "" || getPropertyFromEnvironment(vCertTokenURL) != ""
		jwtPresent := flags.externalJWT != "" || getPropertyFromEnvironment(vCertExternalJWT) != ""
		svcAccountPresent := tokenURLPresent && jwtPresent
		emailPresent := flags.email != ""

		if tokenURLPresent && !jwtPresent {
			return fmt.Errorf("missing jwt for service account authentication. Set the jwt using --external-jwt flag")
		}

		advice := "Use --token-url/--external-jwt for authentication or --email for registration"
		if !svcAccountPresent && !emailPresent {
			return fmt.Errorf("missing flags for CyberArk Certificate Manager, SaaS authentication. %s", advice)
		}

		return nil
	}

	//Any other command
	apiKeyPresent := flags.apiKey != "" || getPropertyFromEnvironment(vCertApiKey) != ""
	tokenPresent := flags.token != "" || getPropertyFromEnvironment(vCertToken) != ""

	advice := "Use only one of --apiKey (-k) or --token (-t)"

	if !apiKeyPresent && !tokenPresent {
		return fmt.Errorf("missing flags for CyberArk Certificate Manager, SaaS authentication. %s", advice)
	}

	return nil
}
