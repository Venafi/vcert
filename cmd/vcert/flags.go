/*
 * Copyright 2020-2023 Venafi, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"sort"
	"strings"

	"github.com/urfave/cli/v2"
)

var (
	flagPlatform = &cli.StringFlag{
		Name: "platform",
		Usage: "Use to specify the platform VCert will use to execute the given command. Only accepted values are:\n" +
			"\t\tFor getcred command: --platform [TPP | VCP | OIDC]\n" +
			"\t\tFor enroll command: --platform [TPP | VCP | FIREFLY]\n" +
			"\t\tFor provision command: --platform [ VCP ]",
		Destination: &flags.platformString,
		Aliases:     []string{"p"},
	}

	flagUrl = &cli.StringFlag{
		Name: "url",
		Usage: "REQUIRED/TPP/Firefly/OIDC. The URL of the service. \n\t\tTPP example: -u https://tpp.example.com" +
			"\n\t\tFirefly example: -u https://firefly.example.com" +
			"\n\t\tOIDC example: -u https://my.okta.domain//oauth2/v1/token",
		Destination: &flags.url,
		Aliases:     []string{"u"},
	}

	flagTokenUrl = &cli.StringFlag{
		Name: "token-url",
		Usage: "REQUIRED/VCP. Use to specify the URL to retrieve an access token for Venafi Control Plane. Use in combination with --external-jwt flag." +
			"\n\t\tExample: --token-url https://api.venafi.cloud/v1/oauth2/v2.0/aaaaaaaa-bbbb-cccc/token",
		Destination: &flags.tokenURL,
	}

	flagUrlDeprecated = &cli.StringFlag{
		Name:        "venafi-saas-url",
		Usage:       "",
		Aliases:     []string{"tpp-url"},
		Destination: &flags.url,
		Hidden:      true,
	}

	flagKey = &cli.StringFlag{
		Name:        "apiKey",
		Usage:       "REQUIRED/VaaS. Your API key for Venafi as a Service.  Example: -k aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		Destination: &flags.apiKey,
		Aliases:     []string{"k"},
	}

	flagExternalJWT = &cli.StringFlag{
		Name:        "external-jwt",
		Usage:       "REQUIRED/VCP. Use to specify the JWT of the Identity Provider associated with the service account that is requesting a new access token for Venafi Control Plane. Use in combination with --token-url option.",
		Destination: &flags.externalJWT,
	}

	flagDeviceURL = &cli.StringFlag{
		Name:        "device-url",
		Usage:       "REQUIRED/Firefly working in device flow. The url endpoint of the OAuth 2.0 identity provider to request a device code. Example for Okta: --device-url https://${yourOktaDomain}/device",
		Destination: &flags.deviceURL,
	}

	flagUser = &cli.StringFlag{
		Name: "username",
		Usage: "Use to specify the username of a Trust Protection Platform or the username of OAuth 2.0 password flow grant." +
			"Required if -p12-file or -t is not present and may not be combined with either.",
		Destination: &flags.userName,
	}

	flagTPPUserDeprecated = &cli.StringFlag{
		Name:        "tpp-user",
		Usage:       "",
		Destination: &flags.userName,
		Hidden:      true,
	}

	flagEmail = &cli.StringFlag{
		Name:        "email",
		Usage:       "REQUIRED/VaaS. Use to specify the email for headless registration on VaaS.",
		Destination: &flags.email,
	}

	flagPassword = &cli.StringFlag{
		Name:        "password",
		Usage:       "Use to specify the Trust Protection Platform user's password or the optional password for the headless registration in VaaS or the password for OAuth 2.0 password flow grant.",
		Destination: &flags.password,
	}

	flagTPPPasswordDeprecated = &cli.StringFlag{
		Name:        "tpp-password",
		Usage:       "",
		Destination: &flags.password,
		Hidden:      true,
	}

	flagToken = &cli.StringFlag{
		Name: "token",
		Usage: "REQUIRED/TPP/VaaS/Firefly. Your access token (or refresh token for getcred) for Trust Protection Platform, Venafi as a Service or Firefly. " +
			"Example: -t Ab01Cd23Ef45Uv67Wx89Yz==",
		Destination: &flags.token,
		Aliases:     []string{"t"},
	}

	flagTrustBundle = &cli.StringFlag{
		Name:        "trust-bundle",
		Usage:       "Use to specify a PEM file name to be used as trust anchors when communicating with the remote server.",
		Destination: &flags.trustBundle,
	}
	flagZone = &cli.StringFlag{
		Name:        "zone",
		Destination: &flags.zone,
		Usage: "REQUIRED. The zone that defines the enrollment configuration. In Trust Protection Platform this is " +
			"equivalent to the policy folder path where the certificate object will be placed. " + UtilityShortName +
			" prepends \\VED\\Policy\\, so you only need to specify child folders under the root Policy folder. " +
			"Example: -z Corp\\Engineering",
		Aliases: []string{"z"},
	}

	flagCADN = &cli.StringFlag{
		Name:        "ca-dn",
		Usage:       "",
		Destination: &flags.caDN,
		Hidden:      true,
	}

	flagKeyCurve = &cli.StringFlag{
		Name:        "key-curve",
		Usage:       "Use to specify the ECDSA key curve. Options include: p256 | p384 | p521",
		Destination: &flags.keyCurveString,
		DefaultText: "p256",
	}

	flagKeyType = &cli.StringFlag{
		Name:        "key-type",
		Usage:       "Use to specify a key type. Options include: rsa | ecdsa",
		Destination: &flags.keyTypeString,
		DefaultText: "rsa",
	}

	flagKeySize = &cli.IntFlag{
		Name:        "key-size",
		Usage:       "Use to specify a key size.",
		Destination: &flags.keySize,
		DefaultText: "2048",
	}

	flagFriendlyName = &cli.StringFlag{
		Name:        "nickname",
		Usage:       "Use to specify a name for the new certificate object that will be created and placed in a policy (which you can specify using the -z option).",
		Destination: &flags.friendlyName,
	}

	flagCommonName = &cli.StringFlag{
		Name:        "commonName",
		Usage:       "Use to specify the `common name` (CN). This is required for enrollment except when providing a CSR file.",
		Destination: &flags.commonName,
		Aliases:     []string{"cn"},
	}

	flagOrg = &cli.StringFlag{
		Name:        "org",
		Usage:       "Use to specify organization (O)",
		Destination: &flags.org,
		Aliases:     []string{"o"},
	}

	flagState = &cli.StringFlag{
		Name:        "state",
		Usage:       "Use to specify state/province (ST)",
		Destination: &flags.state,
		Aliases:     []string{"st"},
	}

	flagCountry = &cli.StringFlag{
		Name:        "country",
		Usage:       "Use to specify country (C)",
		Destination: &flags.country,
		Aliases:     []string{"c"},
	}

	flagLocality = &cli.StringFlag{
		Name:        "locality",
		Usage:       "Use to specify city/locality (L)",
		Destination: &flags.locality,
		Aliases:     []string{"l"},
	}

	flagOrgUnits = &cli.StringSliceFlag{
		Name:  "orgUnit",
		Usage: "Use to specify an organizational unit (OU)",
		//Destination: &flags.orgUnits,
		Aliases: []string{"ou"},
	}

	flagDNSSans = &cli.StringSliceFlag{
		Name: "san-dns",
		Usage: "Use to specify a DNS Subject Alternative Name. " +
			"This option can be repeated to specify more than one value like this: --san-dns test.abc.xyz --san-dns test1.abc.xyz etc.",
	}

	flagIPSans = &cli.StringSliceFlag{
		Name: "san-ip",
		Usage: "Use to specify an IP Address Subject Alternative Name. " +
			"This option can be repeated to specify more than one value like this: --san-ip 1.1.1.1 --san-ip 2.2.2.2 etc.",
	}

	flagEmailSans = &cli.StringSliceFlag{
		Name: "san-email",
		Usage: "Use to specify an Email Subject Alternative Name. " +
			"This option can be repeated to specify more than one value like this: --san-email me@abc.xyz --san-email you@abc.xyz etc.",
	}

	flagURISans = &cli.StringSliceFlag{
		Name: "san-uri",
		Usage: "Use to specify a Uniform Resource Identifier (URI) Subject Alternative Name. " +
			"This option can be repeated to specify more than one value like this: --san-uri https://www.abc.xyz --san-uri spiffe://node.abc.xyz etc.",
	}

	flagUPNSans = &cli.StringSliceFlag{
		Name: "san-upn",
		Usage: "Use to specify a User Principal Name (UPN) Subject Alternative Name. " +
			"This option can be repeated to specify more than one value like this: --san-upn me@abc.xyz --san-upn you@abc.xyz etc.",
		Hidden: true,
	}

	flagFormat = &cli.StringFlag{
		Name: "format",
		Usage: "Use to specify the output format. Options include: pem | json | pkcs12 | jks | legacy-pem | legacy-pkcs12." +
			" If PKCS#12 or JKS formats are specified, the --file parameter is required." +
			" For JKS format, the --jks-alias parameter is required and a password must be provided (see --key-password and --jks-password).",
		Destination: &flags.format,
		Value:       "pem",
	}

	flagJKSAlias = &cli.StringFlag{
		Name:        "jks-alias",
		Usage:       "Use to specify the alias of the entry in the Java keystore. Only applicable with --format jks.",
		Destination: &flags.jksAlias,
		Value:       "",
	}

	flagJKSPassword = &cli.StringFlag{
		Name: "jks-password",
		Usage: "Use to specify a password of at least 6 characters that will protect the Java keystore. Only applicable with --format jks. " +
			"If --jks-password is not specified, the value specified by --key-password (or password prompt) will be used for the store.",
		Destination: &flags.jksPassword,
		Value:       "",
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
		Usage: "Use to exclude credential and password prompts. If you enable the prompt and you enter incorrect information, " +
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
			"\t\tlocal:   The private key and CSR will be generated locally (default for TPP and VaaS. For Firefly it doesn't apply)\n" +
			"\t\tservice: The private key and CSR will be generated at service side(default for Firefly)\n" +
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
		Usage: "Use to specify INI configuration file containing connection details instead\n" +
			"\t\tFor TPP: url, access_token, tpp_zone\n" +
			"\t\tFor VaaS: cloud_apikey, cloud_zone\n" +
			"\t\tTPP & VaaS: trust_bundle, test_mode",
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

	flagCredSsh = &cli.BoolFlag{
		Name:        "ssh",
		Usage:       "Use to request a ssh certificate scope - ssh:manage",
		Destination: &flags.sshCred,
	}

	flagCredPm = &cli.BoolFlag{
		Name:        "pm",
		Usage:       "Use to request policy management scope - configuration:manage",
		Destination: &flags.pmCred,
	}

	flagClientId = &cli.StringFlag{
		Name:        "client-id",
		Usage:       "Use to specify the application that will be using the token.",
		Destination: &flags.clientId,
		Value:       "vcert-cli",
	}

	flagClientSecret = &cli.StringFlag{
		Name:        "client-secret",
		Usage:       "Use to specify the client secret to get authorization from an OAuth 2.0 identity provider.",
		Destination: &flags.clientSecret,
	}

	flagAudience = &cli.StringFlag{
		Name: "audience",
		Usage: "Use to specify the audience param to get an access token for OAuth 2.0 identity providers\n" +
			"\t supporting it like Auth0.",
		Destination: &flags.audience,
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
			"\tappending #D for DigiCert, #E for Entrust, or #M for Microsoft. Example: --valid-days 90#M.\n" +
			"\tThis flag can be used also to provide the valid period for Firefly, but it's preferable to use valid-period flag.\n" +
			"\tIf both flags are provided for Firefly then the valid-period flag will be taken into account.\n",
		Destination: &flags.validDays,
	}

	flagValidPeriod = &cli.StringFlag{
		Name: "valid-period",
		Usage: "Specify the validity period of a certificate needs to be valid expressed as an ISO 8601 duration in Firefly.\n" +
			"\t For Example to set 90 days will be --valid-period P90D.\n" +
			"\t If this flag is not set then the valid-days flag value it will be converted to ISO 8601 format and used.\n",
		Destination: &flags.validPeriod,
	}

	flagPolicyName = &cli.StringFlag{
		Name: "zone",
		Usage: "REQUIRED. Use to specify target zone for applying or retrieving certificate policy. " +
			"In Trust Protection Platform this is the path (DN) of a policy folder and in Venafi as a Service " +
			"this is the name of an Application and Issuing Template separated by a backslash. " +
			"Example: -z Engineering\\Internal Certs",
		Destination: &flags.policyName,
		Aliases:     []string{"z"},
	}

	flagPolicyConfigFile = &cli.StringFlag{
		Name:        "file",
		Usage:       "Use to specify the location of a certificate policy specification. REQUIRED for the setpolicy action",
		Destination: &flags.policySpecLocation,
	}

	flagPolicyStarterConfigFile = &cli.BoolFlag{
		Name:        "starter",
		Usage:       "Use to generate an empty policy specification file, when using this flag credentials should be avoided",
		Destination: &flags.policyConfigStarter,
	}

	flagPolicyVerifyConfigFile = &cli.BoolFlag{
		Name:        "verify",
		Usage:       "Use to verify if a policy specification is valid, when using this flag credentials should be avoided",
		Destination: &flags.verifyPolicyConfig,
	}

	//SSH Certificate flags

	flagKeyId = &cli.StringFlag{
		Name:        "id",
		Usage:       "The identifier of the requested certificate (usually used to determine ownership).",
		Destination: &flags.sshCertKeyId,
	}
	flagObjectName = &cli.StringFlag{
		Name:        "object-name",
		Usage:       "The friendly name for the certificate object. If ObjectName is not specified, then KeyID parameter is used.",
		Destination: &flags.sshCertObjectName,
	}
	flagDestinationAddress = &cli.StringSliceFlag{
		Name: "destination-address",
		Usage: "The address (FQDN/hostname/IP/CIDR) of the destination host where the certificate will be used to authenticate to." +
			"This is applicable for client certificates and used for reporting/auditing only",
	}
	flagValidityHours = &cli.IntFlag{
		Name:        "valid-hours",
		Usage:       "How much time the requester wants to have the certificate valid, the format is hours. ",
		Destination: &flags.sshCertValidHours,
	}

	flagSshCertCa = &cli.StringFlag{
		Name:        "template",
		Usage:       "the certificate issuing template that will be used.",
		Destination: &flags.sshCertTemplate,
	}

	flagSshPubKey = &cli.StringFlag{
		Name:        "public-key",
		Usage:       "if user will provide a public key, local or service generated",
		Value:       "local",
		Destination: &flags.sshCertPubKey,
	}

	flagSshKeySize = &cli.IntFlag{
		Name:        "key-size",
		Usage:       "key size bits, they will be used for creating keypair on case public-key:local",
		Destination: &flags.sshCertKeySize,
	}

	flagSshPassPhrase = &cli.StringFlag{
		Name:        "key-passphrase",
		Usage:       "passphrase for encrypting the private key",
		Destination: &flags.sshCertKeyPassphrase,
	}

	flagPolicyDN = &cli.StringFlag{
		Name:        "folder",
		Usage:       "The DN of the policy folder where the certificate object will be created. If this is not specified, then the policy folder specified on the certificate template will be used.",
		Destination: &flags.sshCertFolder,
	}

	flagForceCommand = &cli.StringFlag{
		Name:        "force-command",
		Usage:       "The requested force command. Example: /usr/scripts/db_backup.sh",
		Destination: &flags.sshCertForceCommand,
	}

	flagSourceAddresses = &cli.StringSliceFlag{
		Name:  "source-address",
		Usage: "The requested source addresses as list of IP/CIDR. Example: 192.168.1.1/24",
	}

	flagSshCertPickupId = &cli.StringFlag{
		Name:        "pickup-id",
		Usage:       "the SSH Certificate DN",
		Destination: &flags.sshCertPickupId,
	}

	flagSshCertGuid = &cli.StringFlag{
		Name:        "guid",
		Usage:       "A value that uniquely identifies the certificate request.",
		Destination: &flags.sshCertGuid,
	}

	flagSshCertExtension = &cli.StringSliceFlag{
		Name: "extension",
		Usage: "The requested certificate extensions. For normal extensions use --extension <value> and " +
			"for key value extensions use --extension <k:v>",
	}

	flagSshCertWindows = &cli.BoolFlag{
		Name:        "windows",
		Usage:       "Use it to add end of lines in MS Windows format \\r\\n",
		Destination: &flags.sshCertWindows,
	}

	flagSshCertPrincipal = &cli.StringSliceFlag{
		Name:  "principal",
		Usage: "The requested principals. If no value is specified, then the default principals from the certificate template will be used.",
	}

	flagSshFileCertEnroll = &cli.StringFlag{
		Name: "file",
		Usage: "Use to specify a file name and a location for the resulting private key, public key, certificate. " +
			"Example: --file /path-to/id_rsa",
		Destination: &flags.sshFileCertEnroll,
		TakesFile:   true,
	}

	flagSshFileGetConfig = &cli.StringFlag{
		Name: "file",
		Usage: "Use to specify a file name and a location for the resulting CA public key. " +
			"Example: --file /path-to/trusted_ca.pub",
		Destination: &flags.sshFileGetConfig,
		TakesFile:   true,
	}

	flagCertificateID = &cli.StringFlag{
		Name:        "certificate-id",
		Usage:       "The id of the certificate to be provisioned to a cloud keystore.",
		Destination: &flags.certificateID,
	}

	flagCertificateIDFile = &cli.StringFlag{
		Name: "certificate-id-file",
		Usage: "Use to specify the file name from where to read or write the Certificate ID. " +
			"Either --certificate-id or --certificate-id-file is required.",
		Destination: &flags.certificateIDFile,
	}

	flagKeystoreID = &cli.StringFlag{
		Name:        "keystore-id",
		Usage:       "The id of the cloud keystore where the certificate will be provisioned.",
		Destination: &flags.keystoreID,
	}

	flagKeystoreName = &cli.StringFlag{
		Name:        "keystore-name",
		Usage:       "The name of the cloud keystore where the certificate will be provisioned. Must be set along with provider-name flag.",
		Destination: &flags.keystoreName,
	}

	flagProviderName = &cli.StringFlag{
		Name:        "provider-name",
		Usage:       "Name of the cloud provider which owns the cloud keystore where the certificate will be provisioned. Must be set along with keystore-name flag.",
		Destination: &flags.providerName,
	}

	flagKeystoreCertName = &cli.StringFlag{
		Name:        "certificate-name",
		Usage:       "Use to specify Cloud Keystore Certificate Name to be set or replaced by provisioned certificate (only for Azure Key Vault and Google Certificate Manager)",
		Destination: &flags.keystoreCertName,
	}

	flagKeystoreARN = &cli.StringFlag{
		Name:        "arn",
		Usage:       "Use to specify AWS Resource Name which provisioned certificate will replace (only for AWS Certificate Manager)",
		Destination: &flags.keystoreARN,
	}

	flagProvisionOutputFile = &cli.StringFlag{
		Name: "file",
		Usage: "Use to specify a file name and a location where the output should be written. " +
			"Example: --file /path-to/provision-output",
		Destination: &flags.provisionOutputFile,
		TakesFile:   true,
	}

	flagProvisionPickupID = &cli.StringFlag{
		Name:        "pickup-id",
		Usage:       "Use to specify the Pickup ID (for VCP is the Request ID) of the certificate to be provisioned.",
		Destination: &flags.provisionPickupID,
	}

	flagProvisionFormat = &cli.StringFlag{
		Name:        "format",
		Usage:       "The format of the operation output: text or JSON. Defaults to text.",
		Destination: &flags.provisionFormat,
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
		flagToken,
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
		flagPlatform,
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
			flagJKSAlias,
			flagJKSPassword,
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
			flagValidPeriod,
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
			flagJKSAlias,
			flagJKSPassword,
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
			flagJKSAlias,
			flagJKSPassword,
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

	retireFlags = flagsApppend(
		credentialsFlags,
		flagThumbprint,
		flagDistinguishedName,
		sortedFlags(flagsApppend(
			commonFlags,
			sortableCredentialsFlags,
		)),
	)

	provisionFlags = flagsApppend(
		credentialsFlags,
		flagPlatform,
		flagKeystoreARN,
		flagCertificateID,
		flagCertificateIDFile,
		flagKeystoreCertName,
		flagProvisionOutputFile,
		flagProvisionFormat,
		flagKeystoreID,
		flagKeystoreName,
		flagProvisionPickupID,
		flagPickupIDFile,
		flagProviderName,
	)

	commonCredFlags = []cli.Flag{flagConfig, flagProfile, flagUrl, flagToken, flagTrustBundle}

	getCredFlags = sortedFlags(flagsApppend(
		flagPlatform,
		commonCredFlags,
		flagClientP12,
		flagClientP12PW,
		flagCredFormat,
		flagEmail,
		flagPassword,
		flagUser,
		flagScope,
		flagCredSsh,
		flagCredPm,
		flagClientId,
		flagClientSecret,
		flagAudience,
		flagDeviceURL,
		commonFlags,
		flagTokenUrl,
		flagExternalJWT,
	))

	checkCredFlags = sortedFlags(flagsApppend(
		commonCredFlags,
		flagCredFormat,
		commonFlags,
	))

	voidCredFlags = sortedFlags(flagsApppend(
		commonCredFlags,
		commonFlags,
	))

	createPolicyFlags = sortedFlags(flagsApppend(
		flagKey,
		flagUrl,
		flagToken,
		flagVerbose,
		flagPolicyName,
		flagPolicyConfigFile,
		flagPolicyVerifyConfigFile,
		flagTrustBundle,
		flagInsecure,
	))

	getPolicyFlags = sortedFlags(flagsApppend(
		flagKey,
		flagUrl,
		flagToken,
		flagVerbose,
		flagPolicyName,
		flagPolicyConfigFile,
		flagPolicyStarterConfigFile,
		flagTrustBundle,
		flagInsecure,
	))

	sshPickupFlags = sortedFlags(flagsApppend(
		flagUrl,
		flagToken,
		flagTrustBundle,
		flagSshCertPickupId,
		flagSshCertGuid,
		flagSshPassPhrase,
		commonFlags,
		flagSshCertWindows,
	))

	sshEnrollFlags = sortedFlags(flagsApppend(
		flagUrl,
		flagToken,
		flagTrustBundle,
		flagKeyId,
		flagObjectName,
		flagDestinationAddress,
		flagValidityHours,
		flagSshCertPrincipal,
		flagPolicyDN,
		flagSshCertExtension,
		flagForceCommand,
		flagSourceAddresses,
		flagSshCertCa,
		flagSshPubKey,
		flagSshKeySize,
		flagSshPassPhrase,
		flagSshCertWindows,
		flagSshFileCertEnroll,
		flagFormat,
		commonFlags,
	))

	sshGetConfigFlags = sortedFlags(flagsApppend(
		flagUrl,
		flagTrustBundle,
		flagToken,
		flagSshCertCa,
		flagSshCertGuid,
		flagSshFileGetConfig,
		flagInsecure,
		flagVerbose,
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
