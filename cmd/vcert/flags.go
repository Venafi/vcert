package main

import (
	"github.com/urfave/cli/v2"
)

var (
	flagUrl = &cli.StringFlag{
		Name:        "u",
		Usage:       "The URL of the Trust Protection Platform WebSDK. Example: -u https://tpp.example.com",
		Destination: &flags.url,
	}

	flagUrlDeprecated = &cli.StringFlag{
		Name:        "venafi-saas-url",
		Usage:       "",
		Aliases:     []string{"tpp-url"},
		Destination: &flags.url,
		Hidden:      true,
	}

	flagKey = &cli.StringFlag{
		Name:        "k",
		Usage:       "Your API Key for Venafi Cloud.  Example: -k xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
		Destination: &flags.apiKey,
	}

	flagTPPUser = &cli.StringFlag{
		Name: "username",
		Usage: "Use to specify the username of a Trust Protection Platform user." +
			"Required if -p12-file or -t is not present and may not be combined with either.",
		Destination: &flags.tppUser,
	}

	flagTPPUserDeprecated = &cli.StringFlag{
		Name:        "username",
		Usage:       "",
		Aliases:     []string{"tpp-user"},
		Destination: &flags.tppUser,
		Hidden:      true,
	}

	flagTPPPassword = &cli.StringFlag{
		Name:        "password",
		Usage:       "Use to specify the Trust Protection Platform user's password.",
		Destination: &flags.tppPassword,
	}

	flagTPPPasswordDeprecated = &cli.StringFlag{
		Name:        "tpp-password",
		Usage:       "Use to specify the Trust Protection Platform user's password.",
		Destination: &flags.tppPassword,
		Hidden:      true,
	}

	flagTPPToken = &cli.StringFlag{
		Name:        "t",
		Usage:       "Your access or refresh token for Trust Protection Platform. Example: -t <tpp access token>",
		Destination: &flags.tppToken,
	}

	flagTrustBundle = &cli.StringFlag{
		Name: "trust-bundle",
		Usage: "Use to specify a PEM file name to be used " +
			"as trust anchors when communicating with the remote server.",
		Destination: &flags.trustBundle,
	}
	flagZone = &cli.StringFlag{
		Name:        "z",
		Destination: &flags.zone,
		Usage: "The zone that defines the enrollment configuration. In Trust Protection Platform this is " +
			"equivelant to the policy path where the certificate object will be stored. " + UtilityShortName +
			" prepends \\VED\\Policy\\, so you only need to specify policy folders within the root Policy folder. " +
			"Example: -z Corp\\Engineering",
	}

	flagCADN = &cli.StringFlag{
		Name:        "ca-dn",
		Usage:       "",
		Destination: &flags.caDN,
		Hidden:      true,
	}

	//todo: problem
	flagKeyCurve = &cli.StringFlag{
		Name:        "key-curve",
		Usage:       "Use to specify the ECDSA key curve. Options include: p256 (default) | p521 | p384",
		Value:       "p256",
		Destination: &flags.keyCurveString,
	}

	//todo: problem
	flagKeyType = &cli.StringFlag{
		Name:        "key-type",
		Usage:       "Use to specify a key type. Options include: rsa (default) | ecdsa",
		Value:       "rsa",
		Destination: &flags.keyTypeString,
	}

	flagKeySize = &cli.IntFlag{
		Name:  "key-size",
		Usage: "Use to specify a key size (default 2048).",
		Value: 2048,
	}

	flagFriendlyName = &cli.StringFlag{
		Name:        "nickname",
		Usage:       "Use to specify a name for the new certificate object that will be created and placed in a policy (which you can specify using the -z option).",
		Destination: &flags.friendlyName,
	}

	flagCommonName = &cli.StringFlag{
		Name:        "cn",
		Usage:       "Use to specify the common name (CN). This is required for enrollment except when providing a CSR file.",
		Destination: &flags.commonName,
	}

	flagOrg = &cli.StringFlag{
		Name:  "o",
		Usage: "",
	}
	flagState = &cli.StringFlag{
		Name:  "st",
		Usage: "",
	}
	flagCountry = &cli.StringFlag{
		Name:  "c",
		Usage: "",
	}
	flagLocality = &cli.StringFlag{
		Name:  "l",
		Usage: "",
	}
	flagOrgUnits = &cli.StringSliceFlag{
		Name:  "ou",
		Usage: "",
	}
	flagDNSSans = &cli.StringSliceFlag{
		Name:  "san-dns",
		Usage: "",
	}
	//todo: problem
	flagIPSans = &cli.StringSliceFlag{
		Name:  "san-ip",
		Usage: "",
	}
	//todo: problem
	flagEmailSans = &cli.StringSliceFlag{
		Name:  "san-email",
		Usage: "",
	}
	flagFormat = &cli.StringFlag{
		Name:  "format",
		Usage: "",
		Value: "pem",
	}
	flagFile = &cli.StringFlag{
		Name:  "file",
		Usage: "",
	}
	flagKeyFile = &cli.StringFlag{
		Name:  "key-file",
		Usage: "",
	}
	flagCertFile = &cli.StringFlag{
		Name:  "cert-file",
		Usage: "",
	}
	flagChainFile = &cli.StringFlag{
		Name:  "chain-file",
		Usage: "",
	}
	flagChainOption = &cli.StringFlag{
		Name:  "chain",
		Usage: "",
		Value: "root-last",
	}
	flagVerbose = &cli.BoolFlag{
		Name: "verbose",
	}
	flagNoPrompt = &cli.BoolFlag{
		Name: "np-prompt",
	}
	flagNoPickup = &cli.BoolFlag{
		Name: "no-pickup",
	}
	flagTestMode = &cli.BoolFlag{
		Name: "test-mode",
	}
	flagTestModeDelay = &cli.IntFlag{
		Name:  "test-mode-delay",
		Usage: "",
		Value: 15,
	}
	flagCSR = &cli.StringFlag{
		Name:  "csr",
		Usage: "",
	}
	flagKeyPassword = &cli.StringFlag{
		Name:  "key-password",
		Usage: "",
	}
	flagPickupIDFile = &cli.StringFlag{
		Name:  "pickup-id-file",
		Usage: "",
	}
	flagTimeout = &cli.IntFlag{
		Name:  "timeout",
		Value: 180,
		Usage: "",
	}
	flagInsecure = &cli.BoolFlag{
		Name:  "insecure",
		Usage: "",
	}
	flagConfig = &cli.StringFlag{
		Name:  "config",
		Usage: "",
	}
	flagProfile = &cli.StringFlag{
		Name:  "profile",
		Usage: "",
	}
	flagClientP12 = &cli.StringFlag{
		Name:  "client-pkcs12",
		Usage: "",
	}
	flagClientP12PW = &cli.StringFlag{
		Name:  "client-pkcs12p-pw",
		Usage: "",
	}

	commonFlags = []cli.Flag{flagInsecure, flagFormat}

	//todo: add over, rename
	enrollFlags1 = []cli.Flag{flagUrl, flagTPPUserDeprecated, flagTPPPasswordDeprecated,
		flagTPPToken, flagKey, flagZone, flagUrlDeprecated, flagCommonName}
)
