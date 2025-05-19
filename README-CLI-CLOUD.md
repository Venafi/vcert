![Venafi](https://raw.githubusercontent.com/Venafi/.github/master/images/Venafi_logo.png)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & VCP](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20VCP-f9a90c)  
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# VCert CLI for Venafi Control Plane

Venafi VCert is a command line tool designed to generate keys and simplify certificate acquisition, eliminating the 
need to write code that's required to interact with the Venafi REST API. VCert is available in 32- and 64-bit versions 
for Linux, Windows, and macOS.

This article applies to the latest version of VCert CLI, which you can [download here](https://github.com/Venafi/vcert/releases/latest).

On macOS and Linux, if you have [Homebrew](https://brew.sh) you can install VCert with:

```shell
brew install venafi/tap/vcert
```

## Quick Links

Use these links to quickly jump to a relevant section lower on this page:

- [VCert CLI for Venafi as a Service](#vcert-cli-for-venafi-control-plane)
  - [Quick Links](#quick-links)
  - [Prerequisites](#prerequisites)
  - [General Command Line Parameters](#general-command-line-parameters)
    - [Environment Variables](#environment-variables)
  - [Certificate Request Parameters](#certificate-request-parameters)
  - [Certificate Retrieval Parameters](#certificate-retrieval-parameters)
  - [Certificate Renewal Parameters](#certificate-renewal-parameters)
  - [Certificate Retire Parameters](#certificate-retire-parameters)
  - [Certificate Provisioning Parameters](#certificate-provisioning-parameters)
  - [Parameters for Applying Certificate Policy](#parameters-for-applying-certificate-policy)
  - [Parameters for Viewing Certificate Policy](#parameters-for-viewing-certificate-policy)
  - [Examples](#examples)
  - [Appendix](#appendix)
    - [Registering and obtaining an API Key](#registering-and-obtaining-an-api-key)
    - [Generating a new key pair and CSR](#generating-a-new-key-pair-and-csr)

## Prerequisites

Review these prerequisites to get started. You'll need the following:

1. Verify that the Venafi Control Plane REST API is accessible from the system where
   VCert will be run. Currently, we support the following regions:
    - [https://api.venafi.cloud](https://api.venafi.cloud/vaas) [US]
    - [https://api.venafi.eu](https://api.eu.venafi.cloud/vaas) [EU]
    - [https://api.au.venafi.cloud](https://api.au.venafi.cloud/vaas) [AU]
    - [https://api.uk.venafi.cloud](https://api.uk.venafi.cloud/vaas) [UK]
    - [https://api.sg.venafi.cloud](https://api.sg.venafi.cloud/vaas) [SG]
    - [https://api.ca.venafi.cloud](https://api.ca.venafi.cloud/vaas) [CA]
2. You have successfully registered for a Venafi Control Plane account, have been granted at least the "Resource Owner" 
role, and know your API key. You can use the `getcred` action to
[register and obtain an API key](#registering-and-obtaining-an-api-key), but you will need an administrator to update 
your role if there are already 3 or more users registered for your company in Venafi Control Plane. Alternatively, you 
have configured a service account, the service account has been granted the "Resource Owner" role, you have the 
`token URL` and have obtained a `JWT` from the Identity Provider associated to the service-account.
3. A CA Account and Issuing Template exist and have been configured with:
    1. Recommended Settings values for:
        1. Organizational Unit (OU)
        2. Organization (O)
        3. City/Locality (L)
        4. State/Province (ST)
        5. Country (C)
    2. Issuing Rules that:
        1. (Recommended) Limits Common Name and Subject Alternative Names that are allowed by your organization
        2. (Recommended) Restricts the Key Length to 2048 or higher
        3. (Recommended) Does not allow Private Key Reuse
4. An Application exists where you are among the owners, and you know the Application Name.
5. An Issuing Template is assigned to the Application, and you know its API Alias.

> 📌 **NOTE**: if you're just testing, you can skip the last 3 items.  Simply specify "Default" for the issuing template 
> alias portion of your zone (e.g. "My Application\Default") and an application with the name you specified will be 
> automatically created for you.

## General Command Line Parameters

The following options apply to the `enroll`, `pickup`, and `renew` actions:

| Flag                 | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--config`           | Use to specify INI configuration file containing connection details. Available parameters: `cloud_apikey`, `cloud_zone`, `trust_bundle`, `test_mode`.                                                                                                                                                                                                                                                                                                                                                            |
| `-k` or `--apiKey`   | Use to specify your API key for Venafi Control Plane.<br/>Example: -k aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee                                                                                                                                                                                                                                                                                                                                                                                                       |
| `--no-prompt`        | Use to exclude password prompts. If you enable the prompt and you enter incorrect information, an error is displayed. This option is useful with scripting.                                                                                                                                                                                                                                                                                                                                                      |
| `-p` or `--platform` | Use to specify Venafi Control Plane as the platform of choice to connect. Accepted value is `vcp`, case-insensitive.                                                                                                                                                                                                                                                                                                                                                                                             |
| `-t` or `--token`    | Use to specify an access token for Venafi Control Plane. You need to set `--platform vcp` or `-p vcp` in order to use access tokens for Venafi Control Plane.                                                                                                                                                                                                                                                                                                                                                    |
| `--test-mode`        | Use to test operations without connecting to Venafi Control Plane. This option is useful for integration tests where the test environment does not have access to Venafi Control Plane. Default is false.                                                                                                                                                                                                                                                                                                        |
| `--test-mode-delay`  | Use to specify the maximum number of seconds for the random test-mode connection delay.  Default is 15 (seconds).                                                                                                                                                                                                                                                                                                                                                                                                |
| `--timeout`          | Use to specify the maximum amount of time to wait in seconds for a certificate to be processed by Venafi Control Plane. Default is 120 (seconds).                                                                                                                                                                                                                                                                                                                                                                |
| `--trust-bundle`     | Use to specify a file with PEM formatted certificates to be used as trust anchors when communicating with Venafi Control Plane.  Generally not needed because VCP is secured by a publicly trusted certificate, but it may be needed if your organization requires VCert to traverse a proxy server. VCert uses the trust store of your operating system for this purpose if not specified.<br/>Example: `--trust-bundle /path-to/bundle.pem`                                                                    |
| `-u` or `--url`      | Use to specify the URL of the Venafi Control Plane API server. Currently, we support the following regions:<br/>- `https://api.venafi.cloud` (US region).<br/>- `https://api.venafi.eu` (EU region).<br/>- `https://api.au.venafi.cloud` (AU region).<br/> - `https://api.uk.venafi.cloud` (UK region).<br/> - `https://api.sg.venafi.cloud` (SG region).<br/> - `https://api.ca.venafi.cloud` (CA region).<br/> If it's omitted, then VCert will default to US region. <br/>Example: `-u https://api.venafi.eu` |
| `--verbose`          | Use to increase the level of logging detail, which is helpful when troubleshooting issues.                                                                                                                                                                                                                                                                                                                                                                                                                       |

### Environment Variables

VCert supports supplying flag values using environment variables:

| Attribute                      | Flag               | Environment Variable |
|--------------------------------|--------------------|----------------------|
| API key                        | `-k` or `--apiKey` | `VCERT_APIKEY`       |
| JWT from Identity Provider     | `--external-jwt`   | `VCERT_EXTERNAL_JWT` |
| Venafi Control Plane token     | `-t` or `--token`  | `VCERT_TOKEN`        |
| Venafi Control Plane token URL | `--token-url`      | `VCERT_TOKEN_URL`    |
| Venafi Control Plane URL       | `-u` or `--url`    | `VCERT_URL`          |
| Venafi platform                | `--platform`       | `VCERT_PLATFORM`     |
| Zone                           | `-z` or `--zone`   | `VCERT_ZONE`         |


## Certificate Request Parameters
API key:
```
vcert enroll -k <api key> --cn <common name> -z <application name\issuing template alias>
```
Access token:
```
vcert enroll -p vcp -t <access token> --cn <common name> -z <application name\issuing template alias>
```
Options:

| Command            | Description                                                                                                                                                                                                                                                                                                                                                                   |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--app-info`       | Use to identify the application requesting the certificate with details like vendor name and vendor product.<br/>Example: `--app-info "Venafi VCert CLI"`                                                                                                                                                                                                                     |
| `--cert-file`      | Use to specify the name and location of an output file that will contain only the end-entity certificate.<br/>Example: `--cert-file /path-to/example.crt`                                                                                                                                                                                                                     |
| `--chain`          | Use to include the certificate chain in the output, and to specify where to place it in the file.<br/>Options: `root-last` (default), `root-first`, `ignore`                                                                                                                                                                                                                  |
| `--chain-file`     | Use to specify the name and location of an output file that will contain only the root and intermediate certificates applicable to the end-entity certificate.                                                                                                                                                                                                                |
| `--cn`             | Use to specify the common name (CN). This is required for Enrollment.                                                                                                                                                                                                                                                                                                         |
| `--csr`            | Use to specify the CSR and private key location. Options: `local` (default), `service`, `file`<br/>- local: private key and CSR will be generated locally<br/>- service: private key and CSR will be generated by a VSatellite in Venafi as a Service<br/>- file: CSR will be read from a file by name<br/>Example: `--csr file:/path-to/example.req`                         |
| `--file`           | Use to specify a name and location of an output file that will contain the private key and certificates when they are not written to their own files using `--key-file`, `--cert-file`, and/or `--chain-file`.<br/>Example: `--file /path-to/keycert.pem`                                                                                                                     |
| `--format`         | Use to specify the output format.  The `--file` option must be used with the PKCS#12 and JKS formats to specify the keystore file. JKS format also requires `--jks-alias` and at least one password (see `--key-password` and `--jks-password`) <br/>Options: `pem` (default), `legacy-pem`, `json`, `pkcs12`, `legacy-pkcs12` (analogous to OpenSSL 3.x -legacy flag), `jks` |
| `--jks-alias`      | Use to specify the alias of the entry in the JKS file when `--format jks` is used                                                                                                                                                                                                                                                                                             |
| `--jks-password`   | Use to specify the keystore password of the JKS file when `--format jks` is used.  If not specified, the `--key-password` value is used for both the key and store passwords                                                                                                                                                                                                  |
| `--key-curve`      | Use to specify the elliptic curve for key generation when `--key-type` is ECDSA.<br/>Options: `p256` (default), `p384`, `p521`                                                                                                                                                                                                                                                |
| `--key-file`       | Use to specify the name and location of an output file that will contain only the private key.<br/>Example: `--key-file /path-to/example.key`                                                                                                                                                                                                                                 |
| `--key-password`   | Use to specify a password for encrypting the private key. For a non-encrypted private key, specify `--no-prompt` without specifying this option. You can specify the password using one of three methods: at the command line, when prompted, or by using a password file.<br/>Example: `--key-password file:/path-to/passwd.txt`                                             |
| `--key-size`       | Use to specify a key size for RSA keys.  Default is 2048.                                                                                                                                                                                                                                                                                                                     |
| `--key-type`       | Use to specify the key algorithm.<br/>Options: `rsa` (default), `ecdsa`                                                                                                                                                                                                                                                                                                       |
| `--no-pickup`      | Use to disable the feature of VCert that repeatedly tries to retrieve the issued certificate.  When this is used you must run VCert again in pickup mode to retrieve the certificate that was requested.                                                                                                                                                                      |
| `--pickup-id-file` | Use to specify a file name where the unique identifier for the certificate will be stored for subsequent use by pickup, renew, and revoke actions.  Default is to write the Pickup ID to STDOUT.                                                                                                                                                                              |
| `--san-dns`        | Use to specify a DNS Subject Alternative Name. To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-dns one.example.com` `--san-dns two.example.com`                                                                                                                                                                                    |
| `--san-email`      | Use to specify an Email Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-email me@example.com` `--san-email you@example.com`                                                                                                                                                                             |
| `--san-ip`         | Use to specify an IP Address Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-ip 10.20.30.40` `--san-ip 192.168.192.168`                                                                                                                                                                                 |
| `--san-uri`        | Use to specify a Uniform Resource Indicator Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-uri spiffe://workload1.example.com` `--san-uri spiffe://workload2.example.com`                                                                                                                              |
| `--valid-days`     | Use to specify the number of days a certificate needs to be valid.<br/>Example: `--valid-days 30`                                                                                                                                                                                                                                                                             |
| `-z`               | Use to specify the name of the Application to which the certificate will be assigned and the API Alias of the Issuing Template that will handle the certificate request.<br/>Example: `-z "Business App\\Enterprise CIT"`                                                                                                                                                     |

## Certificate Retrieval Parameters
API key:
```
vcert pickup -k <api key> [--pickup-id <request id> | --pickup-id-file <file name>]
```
Access token:
```
vcert pickup -p vcp -t <access token> [--pickup-id <request id> | --pickup-id-file <file name>]
```
Options:

| Command            | Description                                                                                                                                                                                                            |
|--------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--cert-file`      | Use to specify the name and location of an output file that will contain only the end-entity certificate.<br/>Example: `--cert-file /path-to/example.crt`                                                              |
| `--chain`          | Use to include the certificate chain in the output, and to specify where to place it in the file.<br/>Options:  `root-last` (default), `root-first`, `ignore`                                                          |
| `--chain-file`     | Use to specify the name and location of an output file that will contain only the root and intermediate certificates applicable to the end-entity certificate.                                                         |
| `--file`           | Use to specify a name and location of an output file that will contain certificates when they are not written to their own files using `--cert-file` and/or `--chain-file`.<br/>Example: `--file /path-to/keycert.pem` |
| `--format`         | Use to specify the output format.<br/>Options: `pem` (default), `json`                                                                                                                                                 |
| `--pickup-id`      | Use to specify the unique identifier of the certificate returned by the enroll or renew actions if `--no-pickup` was used or a timeout occurred. Required when `--pickup-id-file` is not specified.                    |
| `--pickup-id-file` | Use to specify a file name that contains the unique identifier of the certificate returned by the enroll or renew actions if --no-pickup was used or a timeout occurred. Required when `--pickup-id` is not specified. |

## Certificate Renewal Parameters
API key:
```
vcert renew -k <api key> [--id <request id> | --thumbprint <sha1 thumb>]
```
Access token:
```
vcert renew -p vcp -t <access token> [--id <request id> | --thumbprint <sha1 thumb>]
```
Options:

| Command            | Description                                                                                                                                                                                                                                                                                                                                                                   |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--cert-file`      | Use to specify the name and location of an output file that will contain only the end-entity certificate.<br/>Example: `--cert-file /path-to/example.crt`                                                                                                                                                                                                                     |
| `--chain`          | Use to include the certificate chain in the output, and to specify where to place it in the file.<br/>Options: `root-last` (default), `root-first`, `ignore`                                                                                                                                                                                                                  |
| `--chain-file`     | Use to specify the name and location of an output file that will contain only the root and intermediate certificates applicable to the end-entity certificate.                                                                                                                                                                                                                |
| `--cn`             | Use to specify the common name (CN). This is required for Enrollment.                                                                                                                                                                                                                                                                                                         |
| `--csr`            | Use to specify the CSR and private key location. Options: `local` (default), `service`, `file`<br/>- local: private key and CSR will be generated locally<br/>- service: private key and CSR will be generated by a VSatellite in Venafi as a Service<br/>- file: CSR will be read from a file by name<br/>Example: `--csr file:/path-to/example.req`                         |
| `--file`           | Use to specify a name and location of an output file that will contain the private key and certificates when they are not written to their own files using `--key-file`, `--cert-file`, and/or `--chain-file`.<br/>Example: `--file /path-to/keycert.pem`                                                                                                                     |
| `--format`         | Use to specify the output format.  The `--file` option must be used with the PKCS#12 and JKS formats to specify the keystore file. JKS format also requires `--jks-alias` and at least one password (see `--key-password` and `--jks-password`) <br/>Options: `pem` (default), `legacy-pem`, `json`, `pkcs12`, `legacy-pkcs12` (analogous to OpenSSL 3.x -legacy flag), `jks` |
| `--id`             | Use to specify the unique identifier of the certificate returned by the enroll or renew actions.  Value may be specified as a string or read from a file by using the file: prefix.<br/>Example: `--id file:cert_id.txt`                                                                                                                                                      |
| `--jks-alias`      | Use to specify the alias of the entry in the JKS file when `--format jks` is used                                                                                                                                                                                                                                                                                             |
| `--jks-password`   | Use to specify the keystore password of the JKS file when `--format jks` is used.  If not specified, the `--key-password` value is used for both the key and store passwords                                                                                                                                                                                                  |
| `--key-curve`      | Use to specify the elliptic curve for key generation when `--key-type` is ECDSA.<br/>Options: `p256` (default), `p384`, `p521`                                                                                                                                                                                                                                                |
| `--key-file`       | Use to specify the name and location of an output file that will contain only the private key.<br/>Example: `--key-file /path-to/example.key`                                                                                                                                                                                                                                 |
| `--key-password`   | Use to specify a password for encrypting the private key. For a non-encrypted private key, specify `--no-prompt` without specifying this option. You can specify the password using one of three methods: at the command line, when prompted, or by using a password file.                                                                                                    |
| `--key-size`       | Use to specify a key size for RSA keys. Default is 2048.                                                                                                                                                                                                                                                                                                                      |
| `--key-type`       | Use to specify the key algorithm.<br/>Options: `rsa` (default), `ecdsa`                                                                                                                                                                                                                                                                                                       |
| `--no-pickup`      | Use to disable the feature of VCert that repeatedly tries to retrieve the issued certificate.  When this is used you must run VCert again in pickup mode to retrieve the certificate that was requested.                                                                                                                                                                      |
| `--omit-sans`      | Ignore SANs in the previous certificate when preparing the renewal request. Workaround for CAs that forbid any SANs even when the SANs match those the CA automatically adds to the issued certificate.                                                                                                                                                                       |
| `--pickup-id-file` | Use to specify a file name where the unique identifier for the certificate will be stored for subsequent use by `pickup`, `renew`, and `revoke` actions.  By default it is written to STDOUT.                                                                                                                                                                                 |
| `--san-dns`        | Use to specify a DNS Subject Alternative Name. To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-dns one.example.com` `--san-dns two.example.com`                                                                                                                                                                                    |
| `--san-email`      | Use to specify an Email Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-email me@example.com` `--san-email you@example.com`                                                                                                                                                                             |
| `--san-ip`         | Use to specify an IP Address Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-ip 10.20.30.40` `--san-ip 192.168.192.168`                                                                                                                                                                                 |
| `--san-uri`        | Use to specify a Uniform Resource Indicator Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-uri spiffe://workload1.example.com` `--san-uri spiffe://workload2.example.com`                                                                                                                              |
| `--thumbprint`     | Use to specify the SHA1 thumbprint of the certificate to renew. Value may be specified as a string or read from the certificate file using the `file:` prefix.                                                                                                                                                                                                                |

## Certificate Retire Parameters
API key:
```
vcert retire -k <api key> [--id <request id> | --thumbprint <sha1 thumb>]
```
Access Token:
```
vcert retire -p vcp -t <access token> [--id <request id> | --thumbprint <sha1 thumb>]
```
Options:

| Command        | Description                                                                                                                                                     |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--id`         | Use to specify the unique identifier of the certificate to retire.  Value may be specified as a string or read from a file using the `file:` prefix.            |
| `--thumbprint` | Use to specify the SHA1 thumbprint of the certificate to retire. Value may be specified as a string or read from the certificate file using the `file:` prefix. |

## Certificate Provisioning Parameters
API key:
```
vcert provisioning cloudkeystore -p vcp -k <api key> [--certificate-id <certificate id> | --pickup-id <request id> | --pickup-id-file <file name>] [ --keystore-id <keystore id> | --keystore-name <keystore name> --provider-name <provider name>]
```
Access token:
```
vcert provisioning cloudkeystore -p vcp -t <access token> [--certificate-id <certificate id> | --pickup-id <request id> | --pickup-id-file <file name>] [ --keystore-id <keystore id> | --keystore-name <keystore name> --provider-name <provider name>]
```
Options:

| Command                 | Description                                                                                                                                                                                                            |
|-------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--arn`                 | Use to specify AWS Resource Name which provisioned certificate will replace (only for AWS Certificate Manager)                                                                                                         |
| `--certificate-id`      | The id of the certificate to be provisioned to a cloud keystore.                                                                                                                                                       |
| `--certificate-id-file` | Use to specify a file name that contains the unique identifier of the certificate. Required when `--certificate-id` is not specified.                                                                                  |
| `--certificate-name`    | Use to specify Cloud Keystore Certificate Name to be set or replaced by provisioned certificate (only for Azure Key Vault and Google Certificate Manager)                                                              |
| `--file`                | Use to specify a file name and a location where the output should be written. Example: --file /path-to/provision-output                                                                                                |
| `--format`              | The format of the operation output: text or JSON. Defaults to text.                                                                                                                                                    |
| `--keystore-id`         | The id of the cloud keystore where the certificate will be provisioned.                                                                                                                                                |
| `--keystore-name`       | The name of the cloud keystore where the certificate will be provisioned. Must be set along with provider-name flag.                                                                                                   |
| `--pickup-id`           | Use to specify the unique identifier of the certificate returned by the enroll or renew actions. Required when `--pickup-id-file` is not specified.                                                                    |
| `--pickup-id-file`      | Use to specify a file name that contains the unique identifier of the certificate returned by the enroll or renew actions if --no-pickup was used or a timeout occurred. Required when `--pickup-id` is not specified. |
| `--provider-name`       | The name of the cloud provider which owns the cloud keystore where the certificate will be provisioned. Must be set along with keystore-name flag.                                                                     |

## Parameters for Applying Certificate Policy
API key:
```
vcert setpolicy -k <api key> -z <application name\issuing template alias> --file <policy specification file>
```
Access token:
```
vcert setpolicy -p vcp -t <access token> -z <application name\issuing template alias> --file <policy specification file>
```
Options:

| Command    | Description                                                                                                     |
|------------|-----------------------------------------------------------------------------------------------------------------|
| `--file`   | Use to specify the location of the required file that contains a JSON or YAML certificate policy specification. |
| `--verify` | Use to verify that a policy specification is valid. `-k` and `-z` are ignored with this option.                 |

Notes:
- The Venafi certificate policy specification is documented in detail [here](README-POLICY-SPEC.md).
- The PKI Administrator role is required to apply certificate policy.
- Policy (Issuing Template rules) and defaults (Issuing Template recommended settings) revert to their default state if 
they are not present in a policy specification applied by this action.
- If the application or issuing template specified by the `-z` zone parameter do not exist, this action will attempt to 
create them with the calling user as the application owner.
- This action can be used to simply create a new application and/or default issuing template by indicating those names 
with the `-z` zone parameter and applying a file that contains an empty policy (i.e. `{}`).
- If the issuing template specified by the `-z` zone parameter is not already assigned to the application, this action 
will attempt to make that assignment.
- The syntax for the `certificateAuthority` policy value is _CA Account Type\\CA Account Name\\CA Product Name_ 
(e.g. `DIGICERT\\DigiCert SSL Plus\\ssl_plus`).
When not present in the policy specification, `certificateAuthority` defaults to `BUILTIN\\Built-In CA\\Default Product`.
- The `autoInstalled` policy/defaults does not apply as automated installation of certificates by Venafi Control Plane 
is not yet supported.
- The `ellipticCurves` and `serviceGenerated` policy/defaults (`keyPair`) do not apply as ECC and central key generation 
are not yet supported by Venafi Control Plane.
- The `ipAllowed`, `emailAllowed`, `uriAllowed`, and `upnAllowed` policy (`subjectAltNames`) do not apply as those SAN 
types are not yet supported by Venafi Control Plane.
- If undefined key/value pairs are included in the policy specification, they will be silently ignored by this action.
This would include keys that are misspelled.

## Parameters for Viewing Certificate Policy
API key:
```
vcert getpolicy -k <api key> -z <application name\issuing template alias> [--file <policy specification file>]
```
Access token:
```
vcert getpolicy -p vcp -t <access token> -z <application name\issuing template alias> [--file <policy specification file>]
```
Options:

| Command     | Description                                                                                                                |
|-------------|----------------------------------------------------------------------------------------------------------------------------|
| `--file`    | Use to write the retrieved certificate policy to a file in JSON format. If not specified, policy is written to STDOUT.     |
| `--starter` | Use to generate a template policy specification to help with  getting started. `-k` and `-z` are ignored with this option. |

## Examples

For the purposes of the following examples, assume the following:

- The Venafi Control Plane REST API is accessible from the system where
  VCert will be run. Currently, we support the following regions:
    - [https://api.venafi.cloud](https://api.venafi.cloud/vaas) [US]
    - [https://api.venafi.eu](https://api.eu.venafi.cloud/vaas) [EU]
    - [https://api.au.venafi.cloud](https://api.au.venafi.cloud/vaas) [AU]
    - [https://api.uk.venafi.cloud](https://api.uk.venafi.cloud/vaas) [UK]
    - [https://api.sg.venafi.cloud](https://api.sg.venafi.cloud/vaas) [SG]
    - [https://api.ca.venafi.cloud](https://api.ca.venafi.cloud/vaas) [CA]
- A user has been registered and granted at least the `OP Resource Owner` role and has an API key. 
- A CA Account and Issuing Template have been created and configured appropriately (organization, city, state, country, 
key length, allowed domains, etc.). 
- An Application has been created with a name of `Storefront` to which the user has been given access, and the Issuing 
Template has been assigned to the Application with an API Alias of `Public Trust`.

Use the help to view the command line syntax for enroll:
```
vcert enroll -h
```

Submit a request to Venafi Control Plane for enrolling a certificate with a common name of `first-time.venafi.example` 
using an api key and have VCert prompt for the password to encrypt the private key:
```
vcert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z "Storefront\\Public Trust" --cn first-time.venafi.example
```

Submit a request to Venafi Control Plane for enrolling a certificate where the password for encrypting the private key 
to be generated is specified in a text file called passwd.txt:
```
vcert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z "Storefront\\Public Trust" --key-password file:passwd.txt --cn passwd-from-file.venafi.example
```

Submit a request to Venafi Control Plane for enrolling a certificate where the private key to be generated is not 
password encrypted:
```
vcert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z "Storefront\\Public Trust" --cn non-encrypted-key.venafi.example --no-prompt
```

Submit a request to Venafi Control Plane for enrolling a certificate using an externally generated CSR:
```
vcert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z "Storefront\\Public Trust" --csr file:/opt/pki/cert.req
```

Submit a request to Venafi Control Plane for enrolling a certificate where the certificate and private key are output 
using JSON syntax to a file called json.txt:
```
vcert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z "Storefront\\Public Trust" --key-password Passw0rd --cn json-to-file.venafi.example --format json --file keycert.json
```

Submit a request to Venafi Control Plane for enrolling a certificate where only the certificate and private key are 
output, no chain certificates:
```
vcert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z "Storefront\\Public Trust" --key-password Passw0rd --cn no-chain.venafi.example --chain ignore
```

Submit a request to Venafi Control Plane for enrolling a certificate with three DNS subject alternative names:
```
vcert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z "Storefront\\Public Trust" --no-prompt --cn three-sans.venafi.example --san-dns first-san.venafi.example --san-dns second-san.venafi.example --san-dns third-san.venafi.example
```

Submit request to Venafi Control Plane for enrolling a certificate where the certificate is not issued after two 
minutes and then subsequently retrieve that certificate after it has been issued:
```
vcert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z "Storefront\\Public Trust" --no-prompt --cn demo-pickup.venafi.example

vcert pickup -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 --pickup-id "{7428fac3-d0e8-4679-9f48-d9e867a326ca}"
```

Submit request to Venafi Control Plane for enrolling a certificate that will be retrieved later using a Pickup ID from 
a text file:
```
vcert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z "Storefront\\Public Trust" --no-prompt --cn demo-pickup.venafi.example --no-pickup -pickup-id-file pickup_id.txt

vcert pickup -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 --pickup-id-file pickup_id.txt
```

Submit request to Venafi Control Plane for renewing a certificate using the enrollment (pickup) ID of the expiring 
certificate:
```
vcert renew -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 --id "{7428fac3-d0e8-4679-9f48-d9e867a326ca}"
```

Submit request to Venafi Control Plane for renewing a certificate using the expiring certificate file:
```
vcert renew -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 --thumbprint file:/opt/pki/demo.crt
```

## Appendix

### Registering and obtaining an API Key
```
vcert getcred --email <business email address>
```
Options:

| Command      | Description                                                                                                                                                                                                              |
|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--email`    | Use to specify a user's business email address. An email will be sent to this address with a link to activate the API key that is output by this action. This is required for (re)registering with Venafi Control Plane. |
| `--format`   | Specify "json" to get more verbose JSON formatted output instead of the plain text default.                                                                                                                              |
| `--password` | Use to specify the user's password if it is expected the user will need to login to the [Venafi Control Plane web UI](https://ui.venafi.cloud/).                                                                         |

### Obtaining an access token from service account
```
vcert getcred -p vcp --token-url https://api.venafi.cloud/v1/oauth2/v2.0/aaa-bbb-ccc/token --external-jwt "file:jwt.txt"
```
Options:

| Flag                 | Description                                                                                                           |
|----------------------|-----------------------------------------------------------------------------------------------------------------------|
| `-p` or `--platform` | Use to specify Venafi Control Plane as the platform of choice to connect. Accepted value is `vcp`, no case-sensitive. |
| `--token-url`        | The URL used to obtain the access token, provided by Venafi Control Plane's service account page                      |
| `--external-jwt`     | The JWT of the Identity Provider associated to the service account that is going to grant the access token            |

### Generating a new key pair and CSR
```
vcert gencsr --cn <common name> -o <organization> --ou <ou1> --ou <ou2> -l <locality> --st <state> -c <country> --key-file <private key file> --csr-file <csr file>
```

Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                                                                                                                                                                                                                    |
|---------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-c`                                                                                                    | Use to specify the country (C) for the Subject DN.                                                                                                                                                                                                             |
| `--cn`                                                                                                  | Use to specify the common name (CN). This is required for enrollment except when providing a CSR file.                                                                                                                                                         |
| `--csr-file`                                                                                            | Use to specify a file name and a location where the resulting CSR file should be written.<br/>Example: `--csr-file /path-to/example.req`                                                                                                                       |
| `--format`                                                                                              | Generates the Certificate Signing Request in the specified format. Options: `pem` (default), `json`<br />- pem: Generates the CSR in classic PEM format to be used as a file.<br />- json: Generates the CSR in JSON format, suitable for REST API operations. |
| `--key-curve`                                                                                           | Use to specify the ECDSA key curve. Options: `p256` (default), `p384`, `p521`                                                                                                                                                                                  |
| `--key-file`                                                                                            | Use to specify a file name and a location where the resulting private key file should be written. Do not use in combination with `--csr` file.<br/>Example: `--key-file /path-to/example.key`                                                                  |
| `--key-password`                                                                                        | Use to specify a password for encrypting the private key. For a non-encrypted private key, omit this option and instead specify `--no-prompt`.<br/>Example: `--key-password file:/path-to/passwd.txt`                                                          |
| `--key-size`                                                                                            | Use to specify a key size.  Default is 2048.                                                                                                                                                                                                                   |
| `--key-type`                                                                                            | Use to specify a key type. Options: `rsa` (default), `ecdsa`                                                                                                                                                                                                   |
| `-l`                                                                                                    | Use to specify the city or locality (L) for the Subject DN.                                                                                                                                                                                                    |
| `--no-prompt`                                                                                           | Use to suppress the private key password prompt and not encrypt the private key.                                                                                                                                                                               |
| `-o`                                                                                                    | Use to specify the organization (O) for the Subject DN.                                                                                                                                                                                                        |
| `--ou`                                                                                                  | Use to specify an organizational unit (OU) for the Subject DN. To specify more than one, simply repeat this parameter for each value.<br/>Example: `--ou "Engineering"` `--ou "Quality Assurance"` ...                                                         |
| `--san-dns`                                                                                             | Use to specify a DNS Subject Alternative Name. To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-dns one.example.com` `--san-dns two.example.com`                                                                     |
| `--san-email`                                                                                           | Use to specify an Email Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-email me@example.com` `--san-email you@example.com`                                                              |
| `--san-ip`                                                                                              | Use to specify an IP Address Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-ip 10.20.30.40` `--san-ip 192.168.192.168`                                                                  |
| `--san-uri`                                                                                             | Use to specify a Uniform Resource Indicator Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-uri spiffe://workload1.example.com` `--san-uri spiffe://workload2.example.com`               |
| `--st`                                                                                                  | Use to specify the state or province (ST) for the Subject DN.                                                                                                                                                                                                  |
