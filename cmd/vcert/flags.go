package main

import (
	"github.com/urfave/cli/v2"
	"sort"
	"strings"
)

var (
	flagUrl = &cli.StringFlag{
		Name:        "u",
		Usage:       "REQUIRED/TPP. The `URL` of the Trust Protection Platform WebSDK. Example: -u https://tpp.example.com",
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
		Usage:       "REQUIRED/CLOUD. Your API `key` for Venafi Cloud.  Example: -k xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
		Destination: &flags.apiKey,
	}

	flagTPPUser = &cli.StringFlag{
		Name: "username",
		Usage: "Use to specify the username of a Trust Protection Platform user." +
			"Required if -p12-file or -t is not present and may not be combined with either.",
		Destination: &flags.tppUser,
	}

	flagTPPUserDeprecated = &cli.StringFlag{
		Name:        "tpp-user",
		Usage:       "",
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
		Usage:       "",
		Destination: &flags.tppPassword,
		Hidden:      true,
	}

	flagTPPToken = &cli.StringFlag{
		Name:        "t",
		Usage:       "REQUIRED/TPP Your access or refresh `token` for Trust Protection Platform. Example: -t <TPP token>",
		Destination: &flags.tppToken,
	}

	flagTrustBundle = &cli.StringFlag{
		Name: "trust-bundle",
		Usage: "Use to specify a PEM `file` name to be used " +
			"as trust anchors when communicating with the remote server.",
		Destination: &flags.trustBundle,
	}
	flagZone = &cli.StringFlag{
		Name:        "z",
		Destination: &flags.zone,
		Usage: "REQUIRED. The zone that defines the enrollment configuration. In Trust Protection Platform this is " +
			"equivelant to the policy path where the certificate object will be stored. \n\t\t" + UtilityShortName +
			" prepends \\VED\\Policy\\, so you only need to specify policy folders within the root Policy folder. \n" +
			"\t\tExample: -z Corp\\Engineering",
	}

	flagCADN = &cli.StringFlag{
		Name:        "ca-dn",
		Usage:       "",
		Destination: &flags.caDN,
		Hidden:      true,
	}

	flagKeyCurve = &cli.StringFlag{
		Name: "key-curve",
		Usage: "Use to specify the ECDSA key curve. Options include: p256 | p521 | p384	 (Default: p256)",
		Destination: &flags.keyCurveString,
	}

	flagKeyType = &cli.StringFlag{
		Name:        "key-type",
		Usage:       "Use to specify a key type. Options include: rsa | ecdsa (Default: rsa)",
		Destination: &flags.keyTypeString,
	}

	flagKeySize = &cli.IntFlag{
		Name:        "key-size",
		Usage:       "Use to specify a key size (default 2048).",
		Destination: &flags.keySize,
		DefaultText: "2048",
	}

	flagFriendlyName = &cli.StringFlag{
		Name:        "nickname",
		Usage:       "Use to specify a name for the new certificate object that will be created and placed in a policy (which you can specify using the -z option).",
		Destination: &flags.friendlyName,
	}

	flagCommonName = &cli.StringFlag{
		Name:        "cn",
		Usage:       "Use to specify the `common name` (CN). This is required for enrollment except when providing a CSR file.",
		Destination: &flags.commonName,
	}

	flagOrg = &cli.StringFlag{
		Name:        "o",
		Usage:       "Use to specify organization O",
		Destination: &flags.org,
	}

	flagState = &cli.StringFlag{
		Name:        "st",
		Usage:       "Use to specify state ST",
		Destination: &flags.state,
	}

	flagCountry = &cli.StringFlag{
		Name:        "c",
		Usage:       "Use to specify country C",
		Destination: &flags.country,
	}

	flagLocality = &cli.StringFlag{
		Name:        "l",
		Usage:       "Use to specify locality L",
		Destination: &flags.locality,
	}

	flagOrgUnits = &cli.StringSliceFlag{
		Name:  "ou",
		Usage: "Use to specify organization unit OU",
		//Destination: &flags.orgUnits,
	}

	flagDNSSans = &cli.StringSliceFlag{
		Name:  "san-dns",
		Usage: "Use to specify a DNS Subject Alternative Name. To specify more than one, use spaces like this: -san-dns test.abc.xyz -san-dns test1.abc.xyz etc.",
	}

	flagIPSans = &cli.StringSliceFlag{
		Name: "san-ip",
		Usage: "Use to specify an IP Address Subject Alternative Name. " +
			"This option can be repeated to specify more than one value, like this: -san-ip 1.1.1.1 -san-ip 2.2.2.2.",
	}

	flagEmailSans = &cli.StringSliceFlag{
		Name: "san-email",
		Usage: "Use to specify an Email Subject Alternative Name. " +
			"This option can be repeated to specify more than one value, like this: -san-email abc@abc.xyz -san-email def@abc.xyz etc.",
	}

	flagFormat = &cli.StringFlag{
		Name: "format",
		Usage: "Use to specify the output format. Options include: pem | json | pkcs12." +
			" If PKCS#12 format is specified, then all objects should be written using -file option.",
		Destination: &flags.format,
		Value:       "pem",
	}

	flagFile = &cli.StringFlag{
		Name: "file",
		Usage: "Use to specify a file name and a location where the resulting file should be written. " +
			"If this option is used the key, certificate, and chain will be written to the same file. Example: /path-to/newcert.pem",
		Destination: &flags.file,
	}

	flagKeyFile = &cli.StringFlag{
		Name: "key-file",
		Usage: "Use to specify a file name and a location where the resulting private key file should be written. " +
			"Do not use in combination with -csr file. Example: /path-to/newkey.pem",
		Destination: &flags.keyFile,
	}

	flagCertFile = &cli.StringFlag{
		Name: "cert-file",
		Usage: "Use to specify a file name and a location where the resulting " +
			"certificate file should be written. Example: /path-to/newcert.pem",
		Destination: &flags.certFile,
	}

	flagChainFile = &cli.StringFlag{
		Name: "chain-file",
		Usage: "Use to specify a path and file name where the resulting chain file should be written, " +
			"if no chain file is specified the chain will be stored in the same file as the certificate. Example: /path-to/chain.pem",
		Destination: &flags.chainFile,
	}

	flagChainOption = &cli.StringFlag{
		Name: "chain",
		Usage: "Use to include the certificate chain in the output, and to specify where to place it in the file. " +
			"Options include: ignore | root-first | root-last",
		Value:       "root-last",
		Destination: &flags.chainOption,
	}

	flagVerbose = &cli.BoolFlag{
		Name:        "verbose",
		Usage:       "Use to increase the level of logging detail, which is helpful when troubleshooting issues",
		Destination: &flags.verbose,
	}

	flagNoPrompt = &cli.BoolFlag{
		Name: "no-prompt",
		Usage: "Use to exclude the authentication prompt. If you enable the prompt and you enter incorrect information, " +
			"an error is displayed. This is useful with scripting.",
		Destination: &flags.noPrompt,
	}

	flagNoPickup = &cli.BoolFlag{
		Name:        "no-pickup",
		Usage:       "Use to not wait for the certificate to be issued.",
		Destination: &flags.noPickup,
	}

	flagTestMode = &cli.BoolFlag{
		Name: "test-mode",
		Usage: "Use to test enrollment without a connection to a real endpoint." +
			" Options include: true | false",
		Destination: &flags.testMode,
	}

	flagTestModeDelay = &cli.IntFlag{
		Name:        "test-mode-delay",
		Usage:       "Use to specify the maximum, random seconds for a test-mode connection delay.",
		Value:       15,
		Destination: &flags.testModeDelay,
	}

	flagCSROption = &cli.StringFlag{
		Name: "csr",
		Usage: "Use to specify the CSR and private key location. Options include: local | service | file.\n" +
			"\t\tlocal:   The private key and CSR will be generated locally (default)\n" +
			"\t\tservice: The private key and CSR will be generated at service side\n" +
			"\t\tfile:    The CSR will be read from a file by name. Example: file:/path-to/csr.pem",
		Destination: &flags.csrOption,
	}

	flagCSRFile = &cli.StringFlag{
		Name:        "csr-file",
		Usage:       "Use to specify a file name and a location where the resulting CSR file should be written. Example: /tmp/newcsr.pem",
		Destination: &flags.csrFile,
	}

	flagKeyPassword = &cli.StringFlag{
		Name: "key-password",
		Usage: "Use to specify a password for encrypting the private key. " +
			"For a non-encrypted private key, omit this option and instead specify -no-prompt. " +
			"Example: -key-password file:/path-to/mypasswds.txt",
		Destination: &flags.keyPassword,
	}

	flagPickupIDFile = &cli.StringFlag{
		Name:        "pickup-id-file",
		Usage:       "Use to specify file name from where Pickup ID will be read or write. Either -pickup-id or -pickup-id-file is required.",
		Destination: &flags.pickupIDFile,
	}

	flagPickupID = &cli.StringFlag{
		Name:        "pickup-id",
		Usage:       "Use to specify the certificate ID of the certificate for retrieve.",
		Destination: &flags.pickupID,
	}

	flagTimeout = &cli.IntFlag{
		Name:        "timeout",
		Value:       180,
		Usage:       "Time to wait for certificate to be processed at the service side. If 0 - only one retrieve attempt.",
		Destination: &flags.timeout,
	}

	flagInsecure = &cli.BoolFlag{
		Name:        "insecure",
		Usage:       "Skip TLS verify. Only for testing",
		Hidden:      true,
		Destination: &flags.insecure,
	}

	flagConfig = &cli.StringFlag{
		Name: "config",
		Usage: "Use to specify INI configuration `file` containing connection details instead\n" +
			"\t\tFor TPP: url, access_token, tpp_zone\n" +
			"\t\tFor Cloud: cloud_apikey, cloud_zone\n" +
			"\t\tTPP & Cloud: trust_bundle, test_mode",
		Destination: &flags.config,
	}

	flagProfile = &cli.StringFlag{
		Name:        "profile",
		Usage:       "Use to specify effective section in ini-configuration file specified by -config option.",
		Destination: &flags.profile,
	}

	flagClientP12 = &cli.StringFlag{
		Name:        "p12-file",
		Usage:       "Use to specify a client PKCS#12 archive for mutual TLS (for 2FA, use the getcred action to authenticate with Venafi Platform using a client certificate).",
		Destination: &flags.clientP12,
	}

	flagClientP12PW = &cli.StringFlag{
		Name:        "p12-password",
		Usage:       "Use to specify the password for a client PKCS#12 archive. Use in combination with -client-pkcs12 option.",
		Destination: &flags.clientP12PW,
	}

	flagClientP12Deprecated = &cli.StringFlag{
		Name:        "client-pkcs12",
		Usage:       "Use p12-file",
		Destination: &flags.clientP12,
		Hidden:      true,
	}

	flagClientP12PWDeprecated = &cli.StringFlag{
		Name:        "client-pkcs12-pw",
		Usage:       "Use p12-password",
		Destination: &flags.clientP12PW,
		Hidden:      true,
	}

	flagDistinguishedName = &cli.StringFlag{
		Name: "id",
		Usage: "Use to specify the ID of the certificate. Required unless -thumbprint is specified. " +
			"Marks the certificate as disabled and no new certificate will be enrolled to replace the revoked one. " +
			"If a replacement certificate is necessary, also specify -no-retire=true.",
		Destination: &flags.distinguishedName,
	}

	flagThumbprint = &cli.StringFlag{
		Name: "thumbprint",
		Usage: "Use to specify the SHA1 thumbprint of the certificate to renew." +
			" Value may be specified as a string or read from the certificate file using the file: prefix. " +
			"Implies -no-retire=true",
		Destination: &flags.thumbprint,
	}

	//todo: make check agains RevocationReasonOptions[]string variable
	flagRevocationReason = &cli.StringFlag{
		Name: "reason",
		Usage: `The revocation reason. Options include: 
	"none",
	"key-compromise",
	"ca-compromise",
	"affiliation-changed",
	"superseded",
	"cessation-of-operation"`,
		Destination: &flags.revocationReason,
	}

	flagRevocationNoRetire = &cli.StringFlag{
		Name:        "no-retire",
		Usage:       "Do not disable certificate object. Works only with -id <certificate DN>)",
		Destination: &flags.revocationReason,
	}

	flagScope = &cli.StringFlag{
		Name:        "scope",
		Usage:       "Use to request specific scopes and restrictions. \"certificate:manage,revoke;\" is the default.",
		Destination: &flags.scope,
	}

	flagClientId = &cli.StringFlag{
		Name:        "client-id",
		Usage:       "Use to specify the application that will be using the token. \"vcert-cli\" is the default.",
		Destination: &flags.clientId,
	}

	commonFlags              = []cli.Flag{flagInsecure, flagFormat, flagVerbose, flagNoPrompt}
	keyFlags                 = []cli.Flag{flagKeyType, flagKeySize, flagKeyCurve, flagKeyFile, flagKeyPassword}
	sansFlags                = []cli.Flag{flagDNSSans, flagEmailSans, flagIPSans}
	subjectFlags             = flagsApppend(flagCommonName, flagCountry, flagState, flagLocality, flagOrg, flagOrgUnits)
	sortableCredentialsFlags = []cli.Flag{
		flagTestMode,
		flagTestModeDelay,
		flagConfig,
		flagProfile,
		flagUrlDeprecated,
		flagTPPUserDeprecated,
		flagTPPPasswordDeprecated,
		flagClientP12,
		flagClientP12PW,
		flagClientP12Deprecated,
		flagClientP12PWDeprecated,
		flagTrustBundle,
	}

	credentialsFlags = []cli.Flag{
		flagKey,
		flagTPPToken,
		flagUrl,
		delimiter(" "),
	}

	genCsrFlags = sortedFlags(flagsApppend(
		subjectFlags,
		sansFlags,
		flagCSRFile,
		keyFlags,
		flagNoPrompt,
		flagVerbose,
	))

	enrollFlags = flagsApppend(
		flagCommonName,
		flagZone,
		credentialsFlags,
		sortedFlags(flagsApppend(
			sortableCredentialsFlags,
			hiddenFlags(subjectFlags[1:], true), // backward compatibility
			commonFlags,
			flagCADN,
			flagCertFile,
			flagChainFile,
			flagChainOption,
			flagCSROption,
			flagDistinguishedName,
			sansFlags,
			flagFile,
			flagFriendlyName,
			keyFlags,
			flagNoPickup,
			flagPickupIDFile,
			flagTimeout,
		)),
	)

	pickupFlags = flagsApppend(
		credentialsFlags,
		sortedFlags(flagsApppend(
			sortableCredentialsFlags,
			flagCertFile,
			flagChainFile,
			flagChainOption,
			flagFile,
			flagKeyFile,
			flagKeyPassword,
			flagPickupID,
			flagPickupIDFile,
			flagTimeout,
			flagZone,
			commonFlags,
		)),
	)

	revokeFlags = flagsApppend(
		credentialsFlags,
		flagDistinguishedName,
		sortedFlags(flagsApppend(
			flagRevocationNoRetire,
			flagRevocationReason,
			flagThumbprint,
			flagZone,
			commonFlags,
			sortableCredentialsFlags,
		)),
	)

	renewFlags = flagsApppend(
		flagDistinguishedName,
		flagThumbprint,
		credentialsFlags,
		sortedFlags(flagsApppend(
			hiddenFlags(flagZone, true),       //todo: fix aruba tests and remove
			hiddenFlags(flagCommonName, true), //todo: fix aruba tests and remove
			flagCADN,
			flagCertFile,
			flagChainFile,
			flagChainOption,
			flagCSROption,
			flagFriendlyName,
			keyFlags,
			flagNoPickup,
			flagTimeout,
			commonFlags,
			sortableCredentialsFlags,
			flagPickupIDFile,
		)),
	)

	getcredFlags = sortedFlags(flagsApppend(
		flagClientP12,
		flagClientP12PW,
		flagConfig,
		flagProfile,
		flagTPPPassword,
		flagTPPToken,
		flagTPPUser,
		flagTrustBundle,
		flagUrl,
		flagScope,
		flagClientId,
		commonFlags,
	))
)

var delimiterCounter int

func delimiter(text string) *cli.StringFlag {
	delimiterCounter++
	return &cli.StringFlag{Name: strings.Repeat("\u00A0", delimiterCounter), Usage: text + "`\r\t\t" + strings.Repeat(" ", 2+delimiterCounter) + " `"}
}

func flagsApppend(flags ...interface{}) []cli.Flag {
	result := make([]cli.Flag, 0, 100)
	for i := range flags {
		switch flags[i].(type) {
		case cli.Flag:
			result = append(result, flags[i].(cli.Flag))
		case []cli.Flag:
			result = append(result, flags[i].([]cli.Flag)...)
		}
	}
	return result
}

func sortedFlags(a []cli.Flag) []cli.Flag {
	b := make([]cli.Flag, len(a))
	copy(b, a)
	sort.Sort(cli.FlagsByName(b))
	return b
}

func hiddenFlags(fl interface{}, hidden bool) []cli.Flag {
	var flags []cli.Flag
	if f, ok := fl.(cli.Flag); ok {
		flags = append(flags, f)
	}
	if _f, ok := fl.([]cli.Flag); ok {
		flags = _f
	}
	r := make([]cli.Flag, len(flags))
	for i, f := range flags {
		switch v := f.(type) {
		case *cli.StringFlag:
			n := *v
			n.Hidden = hidden
			r[i] = &n
		case *cli.BoolFlag:
			n := *v
			n.Hidden = hidden
			r[i] = &n
		case *cli.IntFlag:
			n := *v
			n.Hidden = hidden
			r[i] = &n
		case *cli.StringSliceFlag:
			n := *v
			n.Hidden = hidden
			r[i] = &n
		}
	}
	return r
}
