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
		Usage:       "REQUIRED/CLOUD. Your API `key` for Venafi Cloud.  Example: -k aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
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
		Name: "t",
		Usage: "REQUIRED/TPP. Your access token (or refresh token if getcred) for Trust Protection Platform. " +
			"Example: -t Ab01Cd23Ef45Uv67Wx89Yz==",
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
			"equivalent to the policy folder path where the certificate object will be placed. " + UtilityShortName +
			" prepends \\VED\\Policy\\, so you only need to specify child folders under the root Policy folder. " +
			"Example: -z Corp\\Engineering",
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
		Usage:       "Use to specify organization (O)",
		Destination: &flags.org,
	}

	flagState = &cli.StringFlag{
		Name:        "st",
		Usage:       "Use to specify state/province (ST)",
		Destination: &flags.state,
	}

	flagCountry = &cli.StringFlag{
		Name:        "c",
		Usage:       "Use to specify country (C)",
		Destination: &flags.country,
	}

	flagLocality = &cli.StringFlag{
		Name:        "l",
		Usage:       "Use to specify city/locality (L)",
		Destination: &flags.locality,
	}

	flagOrgUnits = &cli.StringSliceFlag{
		Name:  "ou",
		Usage: "Use to specify an organizational unit (OU)",
		//Destination: &flags.orgUnits,
	}

	flagDNSSans = &cli.StringSliceFlag{
		Name:  "san-dns",
		Usage: "Use to specify a DNS Subject Alternative Name. To specify more than one, use spaces like this: --san-dns test.abc.xyz --san-dns test1.abc.xyz etc.",
	}

	flagIPSans = &cli.StringSliceFlag{
		Name: "san-ip",
		Usage: "Use to specify an IP Address Subject Alternative Name. " +
			"This option can be repeated to specify more than one value, like this: --san-ip 1.1.1.1 --san-ip 2.2.2.2.",
	}

	flagEmailSans = &cli.StringSliceFlag{
		Name: "san-email",
		Usage: "Use to specify an Email Subject Alternative Name. " +
			"This option can be repeated to specify more than one value, like this: --san-email me@abc.xyz --san-email you@abc.xyz etc.",
	}

	flagURISans = &cli.StringSliceFlag{
		Name: "san-uri",
		Usage: "Use to specify a Uniform Resource Identifier (URI) Subject Alternative Name. " +
			"This option can be repeated to specify more than one value, like this: --san-uri https://www.abc.xyz --san-uri spiffe://node.abc.xyz etc.",
		Hidden: true,
	}

	flagUPNSans = &cli.StringSliceFlag{
		Name: "san-upn",
		Usage: "Use to specify a User Principal Name (UPN) Subject Alternative Name. " +
			"This option can be repeated to specify more than one value, like this: --san-upn me@abc.xyz --san-upn you@abc.xyz etc.",
		Hidden: true,
	}

	flagFormat = &cli.StringFlag{
		Name: "format",
		Usage: "Use to specify the output format. Options include: pem | json | pkcs12." +
			" If PKCS#12 format is specified, then all objects should be written using --file option.",
		Destination: &flags.format,
		Value:       "pem",
	}

	flagFile = &cli.StringFlag{
		Name: "file",
		Usage: "Use to specify a file name and a location where the resulting file should be written. " +
			"If this option is used the key, certificate, and chain will be written to the same file. " +
			"Example: --file /path-to/newcert.pem",
		Destination: &flags.file,
		TakesFile:   true,
	}

	flagKeyFile = &cli.StringFlag{
		Name: "key-file",
		Usage: "Use to specify a file name and a location where the resulting private key file should be written. " +
			"Do not use in combination with --csr file. Example: --key-file /path-to/newkey.pem",
		Destination: &flags.keyFile,
		TakesFile:   true,
	}

	flagCertFile = &cli.StringFlag{
		Name: "cert-file",
		Usage: "Use to specify a file name and a location where the resulting " +
			"certificate file should be written. Example: --cert-file /path-to/newcert.pem",
		Destination: &flags.certFile,
		TakesFile:   true,
	}

	flagChainFile = &cli.StringFlag{
		Name: "chain-file",
		Usage: "Use to specify a path and file name where the resulting chain file should be written, " +
			"if no chain file is specified the chain will be stored in the same file as the certificate. " +
			"Example: --chain-file /path-to/chain.pem",
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
		Value:       false,
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
			"\t\tfile:    The CSR will be read from a file by name. Example: --csr file:/path-to/csr.pem",
		Destination: &flags.csrOption,
	}

	flagCSRFile = &cli.StringFlag{
		Name: "csr-file",
		Usage: "Use to specify a file name and a location where the resulting CSR file should be written. " +
			"Example: --csr-file /tmp/newcsr.pem",
		Destination: &flags.csrFile,
		TakesFile:   true,
	}

	flagKeyPassword = &cli.StringFlag{
		Name: "key-password",
		Usage: "Use to specify a password for encrypting the private key. " +
			"For a non-encrypted private key, omit this option and instead specify --no-prompt. " +
			"Example: --key-password file:/path-to/mypasswd.txt",
		Destination: &flags.keyPassword,
	}

	flagPickupIDFile = &cli.StringFlag{
		Name: "pickup-id-file",
		Usage: "Use to specify the file name from where to read or write the Pickup ID. " +
			"Either --pickup-id or --pickup-id-file is required.",
		Destination: &flags.pickupIDFile,
		TakesFile:   true,
	}

	flagPickupID = &cli.StringFlag{
		Name:        "pickup-id",
		Usage:       "Use to specify the certificate ID of the certificate to retrieve.",
		Destination: &flags.pickupID,
	}

	flagTimeout = &cli.IntFlag{
		Name:        "timeout",
		Value:       180,
		Usage:       "Time to wait for certificate to be processed at the service side. If 0 then only attempt one retrieval.",
		Destination: &flags.timeout,
	}

	flagInsecure = &cli.BoolFlag{
		Name:        "insecure",
		Usage:       "Skip TLS verification. Only for testing.",
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
		TakesFile:   true,
	}

	flagProfile = &cli.StringFlag{
		Name:        "profile",
		Usage:       "Use to specify effective section in INI configuration file specified by --config option.",
		Destination: &flags.profile,
	}

	flagClientP12 = &cli.StringFlag{
		Name:        "p12-file",
		Usage:       "Use to specify a client PKCS#12 archive for mutual TLS (for 2FA, use the getcred action to authenticate with Venafi Platform using a client certificate).",
		Destination: &flags.clientP12,
		TakesFile:   true,
	}

	flagClientP12PW = &cli.StringFlag{
		Name:        "p12-password",
		Usage:       "Use to specify the password for a client PKCS#12 archive. Use in combination with --p12-file option.",
		Destination: &flags.clientP12PW,
	}

	flagClientP12Deprecated = &cli.StringFlag{
		Name:        "client-pkcs12",
		Usage:       "Use p12-file",
		Destination: &flags.clientP12,
		TakesFile:   true,
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
		Usage: "Use to specify the ID of the certificate. Required unless --thumbprint is specified. For revocation," +
			"marks the certificate as disabled so that no new certificate can be enrolled to replace it. " +
			"If a replacement certificate will be enrolled, also specify --no-retire.",
		Destination: &flags.distinguishedName,
	}

	flagThumbprint = &cli.StringFlag{
		Name: "thumbprint",
		Usage: "Use to specify the SHA1 thumbprint of the certificate to renew." +
			" Value may be specified as a string or read from the certificate file using the file: prefix. " +
			"Implies --no-retire.",
		Destination: &flags.thumbprint,
	}

	flagInstance = &cli.StringSliceFlag{
		Name:        "instance",
		Usage:       "Use to provide the name/address of the compute instance and an identifier for the workload using the certificate. Example: --instance node:workload",
		DefaultText: "",
	}

	flagTlsAddress = &cli.StringSliceFlag{
		Name:  "tls-address",
		Usage: "Use to specify the hostname, FQDN or IP address and TCP port where the certificate can be validated after issuance and installation. Example: --tls-address 10.20.30.40:443",
	}

	flagAppInfo = &cli.StringSliceFlag{
		Name:        "app-info",
		Usage:       "Use to identify the application requesting the certificate with details like vendor name, application name, and application version.",
		DefaultText: "",
	}

	flagReplace = &cli.BoolFlag{
		Name:        "replace-instance",
		Usage:       "Force the specified instance to be recreated if it already exists and is associated with the requested certificate.",
		Destination: &flags.replaceInstance,
	}

	//todo: make check agains RevocationReasonOptions[]string variable
	flagRevocationReason = &cli.StringFlag{
		Name: "reason",
		Usage: `The revocation reason. Options include: 
	"none", "key-compromise", "ca-compromise", "affiliation-changed", "superseded", "cessation-of-operation"`,
		Destination: &flags.revocationReason,
	}

	flagRevocationNoRetire = &cli.BoolFlag{
		Name:        "no-retire",
		Usage:       "Do not disable certificate object. Works only with --id <certificate DN>",
		Destination: &flags.noRetire,
	}

	flagScope = &cli.StringFlag{
		Name:        "scope",
		Usage:       "Use to request specific scopes and restrictions.",
		Destination: &flags.scope,
		Value:       "certificate:manage,revoke",
	}

	flagClientId = &cli.StringFlag{
		Name:        "client-id",
		Usage:       "Use to specify the application that will be using the token.",
		Destination: &flags.clientId,
		Value:       "vcert-cli",
	}

	flagCustomField = &cli.StringSliceFlag{
		Name:  "field",
		Usage: "Use to specify custom fields in format 'key=value'. If many values for the same key are required, use syntax '--field key1=value1 --field key1=value2'",
	}

	flagOmitSans = &cli.BoolFlag{
		Name:        "omit-sans",
		Usage:       "Ignore SANs in the previous certificate when preparing the renewal request. Workaround for CAs that forbid any SANs even when the SANs match those the CA automatically adds to the issued certificate.",
		Destination: &flags.omitSans,
	}

	flagCSRFormat = &cli.StringFlag{
		Name: "format",
		Usage: "Generates the Certificate Signing Request in the specified format. Options include: pem | json\n" +
			"\tpem: Generates the CSR in classic PEM format to be used as a file.\n" +
			"\tjson: Generates the CSR in JSON format, suitable for REST API operations.",
		Destination: &flags.csrFormat,
		Value:       "pem",
	}

	flagCredFormat = &cli.StringFlag{
		Name:        "format",
		Usage:       "Use to output credentials in an alternate format. Example: --format json",
		Destination: &flags.credFormat,
	}

	flagValidDays = &cli.StringFlag{
		Name: "valid-days",
		Usage: "Specify the number of days a certificate needs to be valid. For TPP, optionally indicate the target issuer by\n" +
			"\tappending #D for DigiCert, #E for Entrust, or #M for Microsoft. Example: --valid-days 90#M\n",
		Destination: &flags.validDays,
	}

	commonFlags              = []cli.Flag{flagInsecure, flagVerbose, flagNoPrompt}
	keyFlags                 = []cli.Flag{flagKeyType, flagKeySize, flagKeyCurve, flagKeyFile, flagKeyPassword}
	sansFlags                = []cli.Flag{flagDNSSans, flagEmailSans, flagIPSans, flagURISans, flagUPNSans}
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
		flagCSRFormat,
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
			sansFlags,
			flagFile,
			flagFormat,
			flagFriendlyName,
			keyFlags,
			flagNoPickup,
			flagPickupIDFile,
			flagTimeout,
			flagCustomField,
			flagTlsAddress,
			flagAppInfo,
			flagInstance,
			flagReplace,
			flagOmitSans,
			flagValidDays,
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
			flagFormat,
			flagKeyFile,
			flagKeyPassword,
			flagPickupID,
			flagPickupIDFile,
			flagTimeout,
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
			commonFlags,
			sortableCredentialsFlags,
		)),
	)

	renewFlags = flagsApppend(
		flagDistinguishedName,
		flagThumbprint,
		credentialsFlags,
		sortedFlags(flagsApppend(
			hiddenFlags(subjectFlags, true), //todo: fix aruba tests and remove
			flagCADN,
			flagFile,
			flagFormat,
			flagCertFile,
			flagChainFile,
			flagChainOption,
			flagCSROption,
			keyFlags,
			flagNoPickup,
			flagTimeout,
			commonFlags,
			sortableCredentialsFlags,
			flagPickupIDFile,
			flagOmitSans,
		)),
	)

	getcredFlags = sortedFlags(flagsApppend(
		flagClientP12,
		flagClientP12PW,
		flagConfig,
		flagCredFormat,
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
