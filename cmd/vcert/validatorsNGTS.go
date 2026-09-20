package main

import (
	"fmt"
	"regexp"

	"github.com/Venafi/vcert/v5/pkg/venafi"
)

// Workspace IDs are unsigned 32-bit integers rendered as strings, and the
// default workspace of a tenant reuses that tenant's 10-digit TSG ID. Validating
// that here turns the common mistake of passing a workspace *name* into a clear
// error instead of a server-side rejection. If NGTS ever issues workspace IDs
// that are not purely numeric, relaxing this one regex is the only change needed.
var workspaceIDRegex = regexp.MustCompile(`^[0-9]{1,10}$`)

// validateWorkspaceFlag checks that --workspace is only used with NGTS and that
// its value looks like a workspace ID.
func validateWorkspaceFlag() error {
	workspace := flags.workspace
	if workspace == "" {
		workspace = getPropertyFromEnvironment(vcertWorkspace)
	}
	if workspace == "" {
		return nil
	}

	// The platform flag is parsed before the command runs, but when the platform
	// comes from the environment instead we have to resolve it here.
	platform := flags.platform
	if platform == venafi.Undefined {
		platform = venafi.GetPlatformType(getPropertyFromEnvironment(vCertPlatform))
	}

	if platform != venafi.NGTS {
		return fmt.Errorf("--workspace is only applicable to Palo Alto Networks Next-Gen Trust Security (NGTS). Set --platform ngts to use it")
	}

	if !workspaceIDRegex.MatchString(workspace) {
		return fmt.Errorf("invalid workspace %q. A workspace is identified by its numeric ID, not its name", workspace)
	}

	return nil
}

func validateConnectionFlagsNGTS(commandName string) error {
	//sshgetconfig command
	//For now this is not supported by Palo Alto Networks Next-Gen Trust Security (NGTS), but when (if) it does, it is going to be an unauthenticated endpoint, just like CyberArk Certificate Manager, Self-Hosted
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
		return fmt.Errorf("missing flags for Palo Alto Networks Next-Gen Trust Security (NGTS) authentication. %s", advice)
	}

	return nil
}
