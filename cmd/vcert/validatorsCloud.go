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
		tenantIDPresent := flags.vaasTenantID != "" || getPropertyFromEnvironment(vCertTenantID) != ""
		externalJWTPresent := flags.externalJWT != "" || getPropertyFromEnvironment(vCertExternalJWT) != ""
		svcAccountPresent := tenantIDPresent && externalJWTPresent
		emailPresent := flags.email != ""

		if tenantIDPresent && !externalJWTPresent {
			return fmt.Errorf("missing jwt for service account authentication. Set the jwt using --external-jwt flag")
		}

		advice := "Use --tenant-id/--external-jwt for authentication or --email for registration"
		if svcAccountPresent && emailPresent {
			return fmt.Errorf("multiple methods set for Venafi as a Service authentication. %s", advice)
		}

		if !svcAccountPresent && !emailPresent {
			return fmt.Errorf("missing flags for Venafi as a Service authentication. %s", advice)
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

	if apiKeyPresent && tokenPresent {
		return fmt.Errorf("multiple methods set for Venafi as a Service authentication. %s", advice)
	}

	return nil
}
