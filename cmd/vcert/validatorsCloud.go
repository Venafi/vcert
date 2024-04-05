package main

import "fmt"

func validateConnectionFlagsCloud(commandName string) error {
	//sshgetconfig command
	//This is not supported for VaaS as of now, but when (if) it does, it is going to be an unauthenticated endpoint, just like TPP
	if commandName == commandSshGetConfigName {
		return nil
	}

	//getcred command
	if commandName == commandGetCredName {
		tokenURLPresent := flags.tokenURL != "" || getPropertyFromEnvironment(vCertTokenURL) != ""
		jwtPresent := flags.idPJWT != "" || getPropertyFromEnvironment(vCertIdPJWT) != ""
		svcAccountPresent := tokenURLPresent && jwtPresent
		emailPresent := flags.email != ""

		if tokenURLPresent && !jwtPresent {
			return fmt.Errorf("missing jwt for service account authentication. Set the jwt using --idp-jwt flag")
		}

		advice := "Use --token-url/--idp-jwt for authentication or --email for registration"
		if !svcAccountPresent && !emailPresent {
			return fmt.Errorf("missing flags for Venafi Cloud Platform authentication. %s", advice)
		}

		return nil
	}

	//Any other command
	apiKeyPresent := flags.apiKey != "" || getPropertyFromEnvironment(vCertApiKey) != ""
	tokenPresent := flags.token != "" || getPropertyFromEnvironment(vCertToken) != ""

	advice := "Use only one of --apiKey (-k) or --token (-t)"

	if !apiKeyPresent && !tokenPresent {
		return fmt.Errorf("missing flags for Venafi as a Service authentication. %s", advice)
	}

	return nil
}
