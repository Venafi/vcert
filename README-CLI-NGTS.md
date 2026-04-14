[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with Palo Alto NGTS](https://img.shields.io/badge/Compatibility-Palo_Alto_NGTS-f9a90c)  
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# VCert CLI for Palo Alto Networks Next-Gen Trust Security (NGTS)

VCert is a command line tool designed to generate keys and simplify certificate acquisition, eliminating the 
need to write code that's required to interact with the REST API. VCert is available in 32- and 64-bit versions 
for Linux, Windows, and macOS.

This article applies to the latest version of VCert CLI, which you can [download here](https://github.com/Venafi/vcert/releases/latest).

On macOS and Linux, if you have [Homebrew](https://brew.sh) you can install VCert with:

```shell
brew install venafi/tap/vcert
```

## Quick Links

Use these links to quickly jump to a relevant section lower on this page:

- [VCert CLI for Palo Alto Networks Next-Gen Trust Security (NGTS)](#vcert-cli-for-palo-alto-networks-next-gen-trust-security-ngts)
  - [Quick Links](#quick-links)
  - [Prerequisites](#prerequisites)
  - [General Command Line Parameters](#general-command-line-parameters)
    - [Environment Variables](#environment-variables)
  - [Certificate Request Parameters](#certificate-request-parameters)
  - [Certificate Retrieval Parameters](#certificate-retrieval-parameters)
  - [Certificate Renewal Parameters](#certificate-renewal-parameters)
  - [Certificate Revocation Parameters](#certificate-revocation-parameters)
  - [Certificate Retire Parameters](#certificate-retire-parameters)
  - [Certificate Provisioning Parameters](#certificate-provisioning-parameters)
  - [Parameters for Applying Certificate Policy](#parameters-for-applying-certificate-policy)
  - [Parameters for Viewing Certificate Policy](#parameters-for-viewing-certificate-policy)
  - [Examples](#examples)
  - [Appendix](#appendix)
    - [Obtaining an Access Token](#obtaining-an-access-token)
    - [Generating a new key pair and CSR](#generating-a-new-key-pair-and-csr)

## Prerequisites

Review these prerequisites to get started. You'll need the following:

1. Verify that the Palo Alto Networks NGTS API is accessible from the system where VCert will be run:
    - `https://api.sase.paloaltonetworks.com`
2. You have successfully registered a Palo Alto Networks NGTS service account and the service account has been granted appropriate 
permissions to manage certificates. See the [Palo Alto Networks service account documentation](https://pan.dev/scm/docs/service-accounts/) for more information about service accounts. The table below     
   shows the minimum required NGTS permissions for each command:

| Command | Required NGTS Permissions |
|---------|---------------------------|
| enroll | `ngts.application_issuing_template.get`, `ngts.application.get`, `ngts.certificate_request.create`, `ngts.certificate_request.get`, `ngts.certificate_content.get` |
| pickup | `ngts.certificate_request.get`, `ngts.certificate.get`, `ngts.edge_encryption_key.get`, `ngts.certificate_content.get` |
| renew | `ngts.certificate.search`, `ngts.certificate_content.get`, `ngts.certificate_request.get`, `ngts.certificate.get`, `ngts.certificate_request.create` |
| retire | `ngts.certificate.search`, `ngts.certificate_request.get`, `ngts.certificate.retire` |
| provision | `ngts.certificate.get`, `ngts.cloud_keystore.list`, `ngts.cloud_keystore.provision` |
| getpolicy | `ngts.application_issuing_template.get`, `ngts.certificate_authority_account.get` |
| setpolicy | `ngts.certificate_authority_account.get`, `ngts.certificate_issuing_template.get`, `ngts.certificate_issuing_template.update`, `ngts.application.get`, `ngts.application_issuing_template.get` |

3. You have either:
    - An OAuth access token for authentication, OR
    - You can use the [getcred command](#obtaining-an-access-token) to obtain an access token with your service account credentials (Client ID, Client Secret, Token URL, and Scope)
4. A CA Account and Issuing Template exist and have been configured with:
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
5. An Application exists and you know the Application Name.
6. An Issuing Template is assigned to the Application, and you know its API Alias.

> 📌 **NOTE**: NGTS uses OAuth-based authentication. You can either provide an access token directly or use service 
> account credentials to obtain one using the `getcred` action.

## General Command Line Parameters

The following options apply to the `enroll`, `pickup`, and `renew` actions:

| Flag                 | Description                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--config`           | Use to specify INI configuration file containing connection details. Available parameters: `url`, `ngts_access_token`, `ngts_client_id`, `ngts_client_secret`, `ngts_scope`, `ngts_token_url`, `trust_bundle`, `test_mode`.                                                                                                                                                                                                                      |
| `--no-prompt`        | Use to exclude password prompts. If you enable the prompt and you enter incorrect information, an error is displayed. This option is useful with scripting.                                                                                                                                                                                                                                                                                      |
| `-p` or `--platform` | Use to specify Palo Alto Networks NGTS as the platform of choice to connect. Accepted value is `ngts`, case-insensitive.                                                                                                                                                                                                                                                                                                                         |
| `-t` or `--token`    | Use to specify an access token for Palo Alto Networks NGTS. You need to set `--platform ngts` or `-p ngts` in order to use access tokens for NGTS.                                                                                                                                                                                                                                                                                               |
| `--test-mode`        | Use to test operations without connecting to Palo Alto Networks NGTS. This option is useful for integration tests where the test environment does not have access to NGTS. Default is false.                                                                                                                                                                                                                                                     |
| `--test-mode-delay`  | Use to specify the maximum number of seconds for the random test-mode connection delay.  Default is 15 (seconds).                                                                                                                                                                                                                                                                                                                                |
| `--timeout`          | Use to specify the maximum amount of time to wait in seconds for a certificate to be processed by Palo Alto Networks NGTS. Default is 120 (seconds).                                                                                                                                                                                                                                                                                             |
| `--trust-bundle`     | Use to specify a file with PEM formatted certificates to be used as trust anchors when communicating with Palo Alto Networks NGTS. Generally not needed because NGTS is secured by a publicly trusted certificate, but it may be needed if your organization requires VCert to traverse a proxy server. VCert uses the trust store of your operating system for this purpose if not specified.<br/>Example: `--trust-bundle /path-to/bundle.pem` |
| `-u` or `--url`      | Use to specify the URL of the Palo Alto Networks NGTS API server.<br/>Default: `https://api.sase.paloaltonetworks.com`<br/>Example: `-u https://api.sase.paloaltonetworks.com`                                                                                                                                                                                                                                                                   |
| `--verbose`          | Use to increase the level of logging detail, which is helpful when troubleshooting issues.                                                                                                                                                                                                                                                                                                                                                       |

### Environment Variables

VCert supports supplying flag values using environment variables:

| Attribute                           | Flag              | Environment Variable     |
|-------------------------------------|-------------------|--------------------------|
| Palo Alto NGTS access token         | `-t` or `--token` | `VCERT_TOKEN`            |
| Palo Alto NGTS URL                  | `-u` or `--url`   | `VCERT_URL`              |
| Platform                            | `--platform`      | `VCERT_PLATFORM`         |
| Zone                                | `-z` or `--zone`  | `VCERT_ZONE`             |
| Service Account Token URL           | `--token-url`     | `VCERT_TOKEN_URL`        |
| Service Account Client ID           | `--client-id`     | `VCERT_CLIENT_ID`        |
| Service Account Client Secret       | `--client-secret` | `VCERT_CLIENT_SECRET`    |
| Service Account Scope               | `--scope`         | `VCERT_SCOPE`            |


## Certificate Request Parameters
Access token:
```
vcert enroll -p ngts -t <access token> --cn <common name> -z <application name\issuing template alias>
```
Options:

| Command            | Description                                                                                                                                                                                                                                                                                                                                                                                   |
|--------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--app-info`       | Use to identify the application requesting the certificate with details like vendor name and vendor product.<br/>Example: `--app-info "Venafi VCert CLI"`                                                                                                                                                                                                                                     |
| `--cert-file`      | Use to specify the name and location of an output file that will contain only the end-entity certificate.<br/>Example: `--cert-file /path-to/example.crt`                                                                                                                                                                                                                                     |
| `--chain`          | Use to include the certificate chain in the output, and to specify where to place it in the file.<br/>Options: `root-last` (default), `root-first`, `ignore`                                                                                                                                                                                                                                  |
| `--chain-file`     | Use to specify the name and location of an output file that will contain only the root and intermediate certificates applicable to the end-entity certificate.                                                                                                                                                                                                                                |
| `--cn`             | Use to specify the common name (CN). This is required for Enrollment.                                                                                                                                                                                                                                                                                                                         |
| `--csr`            | Use to specify the CSR and private key location. Options: `local` (default), `file`<br/>- local: private key and CSR will be generated locally<br/>- file: CSR will be read from a file by name<br/>Example: `--csr file:/path-to/example.req`                                                                                                                                                |
| `--file`           | Use to specify a name and location of an output file that will contain the private key and certificates when they are not written to their own files using `--key-file`, `--cert-file`, and/or `--chain-file`.<br/>Example: `--file /path-to/keycert.pem`                                                                                                                                     |
| `--format`         | Use to specify the output format.  The `--file` option must be used with the PKCS#12 and JKS formats to specify the keystore file. JKS format also requires `--jks-alias` and at least one password (see `--key-password` and `--jks-password`) <br/>Options: `pem` (default), `legacy-pem`, `json`, `pkcs12`, `legacy-pkcs12` (analogous to OpenSSL 3.x -legacy flag), `jks`                 |
| `--jks-alias`      | Use to specify the alias of the entry in the JKS file when `--format jks` is used                                                                                                                                                                                                                                                                                                             |
| `--jks-password`   | Use to specify the keystore password of the JKS file when `--format jks` is used.  If not specified, the `--key-password` value is used for both the key and store passwords                                                                                                                                                                                                                  |
| `--key-curve`      | Use to specify the elliptic curve for key generation when `--key-type` is ECDSA.<br/>Options: `p256` (default), `p384`, `p521`                                                                                                                                                                                                                                                                |
| `--key-file`       | Use to specify the name and location of an output file that will contain only the private key.<br/>Example: `--key-file /path-to/example.key`                                                                                                                                                                                                                                                 |
| `--key-password`   | Use to specify a password for encrypting the private key. For a non-encrypted private key, specify `--no-prompt` without specifying this option. You can specify the password using one of three methods: at the command line, when prompted, or by using a password file.<br/>Example: `--key-password file:/path-to/passwd.txt`                                                             |
| `--key-size`       | Use to specify a key size for RSA keys.  Default is 2048.                                                                                                                                                                                                                                                                                                                                     |
| `--key-type`       | Use to specify the key algorithm.<br/>Options: `rsa` (default), `ecdsa`                                                                                                                                                                                                                                                                                                                       |
| `--no-pickup`      | Use to disable the feature of VCert that repeatedly tries to retrieve the issued certificate.  When this is used you must run VCert again in pickup mode to retrieve the certificate that was requested.                                                                                                                                                                                      |
| `--pickup-id-file` | Use to specify a file name where the unique identifier for the certificate will be stored for subsequent use by pickup, renew, and revoke actions.  Default is to write the Pickup ID to STDOUT.                                                                                                                                                                                              |
| `--san-dns`        | Use to specify a DNS Subject Alternative Name. To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-dns one.example.com` `--san-dns two.example.com`                                                                                                                                                                                                    |
| `--san-email`      | Use to specify an Email Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-email me@example.com` `--san-email you@example.com`                                                                                                                                                                                             |
| `--san-ip`         | Use to specify an IP Address Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-ip 10.20.30.40` `--san-ip 192.168.192.168`                                                                                                                                                                                                 |
| `--san-uri`        | Use to specify a Uniform Resource Indicator Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-uri spiffe://workload1.example.com` `--san-uri spiffe://workload2.example.com`                                                                                                                                              |
| `--valid-days`     | Use to specify the number of days a certificate needs to be valid.<br/>Example: `--valid-days 30`                                                                                                                                                                                                                                                                                             |
| `-z`               | Use to specify the name of the Application to which the certificate will be assigned and the API Alias of the Issuing Template that will handle the certificate request.<br/>Example: `-z "Business App\\Enterprise CIT"`                                                                                                                                                     |

## Certificate Retrieval Parameters
Access token:
```
vcert pickup -p ngts -t <access token> [--pickup-id <request id> | --pickup-id-file <file name>]
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
Access token:
```
vcert renew -p ngts -t <access token> [--id <request id> | --thumbprint <sha1 thumb>]
```
Options:

| Command            | Description                                                                                                                                                                                                                                                                                                                                                                  |
|--------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--cert-file`      | Use to specify the name and location of an output file that will contain only the end-entity certificate.<br/>Example: `--cert-file /path-to/example.crt`                                                                                                                                                                                                                    |
| `--chain`          | Use to include the certificate chain in the output, and to specify where to place it in the file.<br/>Options: `root-last` (default), `root-first`, `ignore`                                                                                                                                                                                                                 |
| `--chain-file`     | Use to specify the name and location of an output file that will contain only the root and intermediate certificates applicable to the end-entity certificate.                                                                                                                                                                                                               |
| `--cn`             | Use to specify the common name (CN). This is required for Enrollment.                                                                                                                                                                                                                                                                                                        |
| `--csr`            | Use to specify the CSR and private key location. Options: `local` (default), `file`<br/>- local: private key and CSR will be generated locally<br/>- file: CSR will be read from a file by name<br/>Example: `--csr file:/path-to/example.req`                                                                                                                               |
| `--file`           | Use to specify a name and location of an output file that will contain the private key and certificates when they are not written to their own files using `--key-file`, `--cert-file`, and/or `--chain-file`.<br/>Example: `--file /path-to/keycert.pem`                                                                                                                    |
| `--format`         | Use to specify the output format. The `--file` option must be used with the PKCS#12 and JKS formats to specify the keystore file. JKS format also requires `--jks-alias` and at least one password (see `--key-password` and `--jks-password`) <br/>Options: `pem` (default), `legacy-pem`, `json`, `pkcs12`, `legacy-pkcs12` (analogous to OpenSSL 3.x -legacy flag), `jks` |
| `--id`             | Use to specify the unique identifier of the certificate returned by the enroll or renew actions.  Value may be specified as a string or read from a file by using the file: prefix.<br/>Example: `--id file:cert_id.txt`                                                                                                                                                     |
| `--jks-alias`      | Use to specify the alias of the entry in the JKS file when `--format jks` is used                                                                                                                                                                                                                                                                                            |
| `--jks-password`   | Use to specify the keystore password of the JKS file when `--format jks` is used.  If not specified, the `--key-password` value is used for both the key and store passwords                                                                                                                                                                                                 |
| `--key-curve`      | Use to specify the elliptic curve for key generation when `--key-type` is ECDSA.<br/>Options: `p256` (default), `p384`, `p521`                                                                                                                                                                                                                                               |
| `--key-file`       | Use to specify the name and location of an output file that will contain only the private key.<br/>Example: `--key-file /path-to/example.key`                                                                                                                                                                                                                                |
| `--key-password`   | Use to specify a password for encrypting the private key. For a non-encrypted private key, specify `--no-prompt` without specifying this option. You can specify the password using one of three methods: at the command line, when prompted, or by using a password file.                                                                                                   |
| `--key-size`       | Use to specify a key size for RSA keys. Default is 2048.                                                                                                                                                                                                                                                                                                                     |
| `--key-type`       | Use to specify the key algorithm.<br/>Options: `rsa` (default), `ecdsa`                                                                                                                                                                                                                                                                                                      |
| `--no-pickup`      | Use to disable the feature of VCert that repeatedly tries to retrieve the issued certificate.  When this is used you must run VCert again in pickup mode to retrieve the certificate that was requested.                                                                                                                                                                     |
| `--omit-sans`      | Ignore SANs in the previous certificate when preparing the renewal request. Workaround for CAs that forbid any SANs even when the SANs match those the CA automatically adds to the issued certificate.                                                                                                                                                                      |
| `--pickup-id-file` | Use to specify a file name where the unique identifier for the certificate will be stored for subsequent use by `pickup`, `renew`, and `revoke` actions.  By default it is written to STDOUT.                                                                                                                                                                                |
| `--san-dns`        | Use to specify a DNS Subject Alternative Name. To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-dns one.example.com` `--san-dns two.example.com`                                                                                                                                                                                   |
| `--san-email`      | Use to specify an Email Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-email me@example.com` `--san-email you@example.com`                                                                                                                                                                            |
| `--san-ip`         | Use to specify an IP Address Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-ip 10.20.30.40` `--san-ip 192.168.192.168`                                                                                                                                                                                |
| `--san-uri`        | Use to specify a Uniform Resource Indicator Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-uri spiffe://workload1.example.com` `--san-uri spiffe://workload2.example.com`                                                                                                                             |
| `--thumbprint`     | Use to specify the SHA1 thumbprint of the certificate to renew. Value may be specified as a string or read from the certificate file using the `file:` prefix.                                                                                                                                                                                                               |

## Certificate Revocation Parameters
```
vcert revoke -p ngts -t <access token> --thumbprint <cert SHA1 thumbprint>
```
Options:

| Command             | Description                                                                                                                                 |
|---------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| `--thumbprint`      | Use to specify the SHA1 thumbprint of the certificate to revoke. Value may be specified as a string or read from the certificate file using the `file:` prefix. |
| `--ca-account-name` | The Certificate Authority Account name. Optional when the certificate to revoke was issued by Palo Alto NGTS. Otherwise it's required to provide it. |
| `--reason`          | Use to specify the revocation reason.<br/>Options: `none` (default), `key-compromise`, `affiliation-changed`, `superseded`, `cessation-of-operation`.  |
| `--comments`        | Use it to add comments to the certificate revocation.                                                                                       |

## Certificate Retire Parameters
Access Token:
```
vcert retire -p ngts -t <access token> [--id <request id> | --thumbprint <sha1 thumb>]
```
Options:

| Command        | Description                                                                                                                                                     |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--id`         | Use to specify the unique identifier of the certificate to retire.  Value may be specified as a string or read from a file using the `file:` prefix.            |
| `--thumbprint` | Use to specify the SHA1 thumbprint of the certificate to retire. Value may be specified as a string or read from the certificate file using the `file:` prefix. |

## Certificate Provisioning Parameters
Access token:
```
vcert provisioning cloudkeystore -p ngts -t <access token> [--certificate-id <certificate id> | --pickup-id <request id> | --pickup-id-file <file name>] [ --keystore-id <keystore id> | --keystore-name <keystore name> --provider-name <provider name>] --certificate-name <certificate name>
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
Access token:
```
vcert setpolicy -p ngts -t <access token> -z <application name\issuing template alias> --file <policy specification file>
```
Options:

| Command    | Description                                                                                                     |
|------------|-----------------------------------------------------------------------------------------------------------------|
| `--file`   | Use to specify the location of the required file that contains a JSON or YAML certificate policy specification. |
| `--verify` | Use to verify that a policy specification is valid. `-t` and `-z` are ignored with this option.                 |

Notes:
- The certificate policy specification is documented in detail [here](README-POLICY-SPEC.md).
- Appropriate permissions are required to apply certificate policy.
- Policy (Issuing Template rules) and defaults (Issuing Template recommended settings) revert to their default state if 
they are not present in a policy specification applied by this action.
- If the issuing template specified by the `-z` zone parameter do not exist, this action will attempt to 
create it.
- If the issuing template specified by the `-z` zone parameter is not already assigned to the application, this action 
will attempt to make that assignment.
- The syntax for the `certificateAuthority` policy value is _CA Account Type\\CA Account Name\\CA Product Name_
  (e.g. `DIGICERT\\DigiCert SSL Plus\\ssl_plus`).
  When not present in the policy specification, `certificateAuthority` defaults to `BUILTIN\\Built-In CA\\Default Product`.
- The `autoInstalled` policy/defaults does not apply as automated installation of certificates by Palo Alto Networks Next-Gen Trust Security (NGTS)
  is not yet supported.
- The `ellipticCurves` and `serviceGenerated` policy/defaults (`keyPair`) do not apply as ECC and central key generation
  are not yet supported by Palo Alto Networks Next-Gen Trust Security (NGTS).
- The `ipAllowed`, `emailAllowed`, `uriAllowed`, and `upnAllowed` policy (`subjectAltNames`) do not apply as those SAN
  types are not yet supported by Palo Alto Networks Next-Gen Trust Security (NGTS).
- If undefined key/value pairs are included in the policy specification, they will be silently ignored by this action.
This would include keys that are misspelled.

## Parameters for Viewing Certificate Policy
Access token:
```
vcert getpolicy -p ngts -t <access token> -z <application name\issuing template alias> [--file <policy specification file>]
```
Options:

| Command     | Description                                                                                                                |
|-------------|----------------------------------------------------------------------------------------------------------------------------|
| `--file`    | Use to write the retrieved certificate policy to a file in JSON format. If not specified, policy is written to STDOUT.     |
| `--starter` | Use to generate a template policy specification to help with  getting started. `-t` and `-z` are ignored with this option. |

## Examples

For the purposes of the following examples, assume the following:

- The Palo Alto Networks NGTS API is accessible at `https://api.sase.paloaltonetworks.com`
- A service account has been registered and granted the needed permissions and you have obtained an OAuth access token. 
- A CA Account and Issuing Template have been created and configured appropriately (organization, city, state, country, 
key length, allowed domains, etc.). 
- An Application has been created with a name of `Storefront` to which the service account has been given access, and the Issuing 
Template has been assigned to the Application with an API Alias of `Public Trust`.

Use the help to view the command line syntax for enroll:
```
vcert enroll -h
```

Submit a request to Palo Alto NGTS for enrolling a certificate with a common name of `first-time.venafi.example` 
using an access token and have VCert prompt for the password to encrypt the private key:
```
vcert enroll -p ngts -t eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... -z "Storefront\\Public Trust" --cn first-time.venafi.example
```

Submit a request to Palo Alto NGTS for enrolling a certificate where the password for encrypting the private key 
to be generated is specified in a text file called passwd.txt:
```
vcert enroll -p ngts -t eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... -z "Storefront\\Public Trust" --key-password file:passwd.txt --cn passwd-from-file.venafi.example
```

Submit a request to Palo Alto NGTS for enrolling a certificate where the private key to be generated is not 
password encrypted:
```
vcert enroll -p ngts -t eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... -z "Storefront\\Public Trust" --cn non-encrypted-key.venafi.example --no-prompt
```

Submit a request to Palo Alto NGTS for enrolling a certificate using an externally generated CSR:
```
vcert enroll -p ngts -t eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... -z "Storefront\\Public Trust" --csr file:/opt/pki/cert.req
```

Submit a request to Palo Alto NGTS for enrolling a certificate where the certificate and private key are output 
using JSON syntax to a file called keycert.json:
```
vcert enroll -p ngts -t eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... -z "Storefront\\Public Trust" --key-password Passw0rd --cn json-to-file.venafi.example --format json --file keycert.json
```

Submit a request to Palo Alto NGTS for enrolling a certificate where only the certificate and private key are 
output, no chain certificates:
```
vcert enroll -p ngts -t eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... -z "Storefront\\Public Trust" --key-password Passw0rd --cn no-chain.venafi.example --chain ignore
```

Submit a request to Palo Alto NGTS for enrolling a certificate with three DNS subject alternative names:
```
vcert enroll -p ngts -t eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... -z "Storefront\\Public Trust" --no-prompt --cn three-sans.venafi.example --san-dns first-san.venafi.example --san-dns second-san.venafi.example --san-dns third-san.venafi.example
```

Submit request to Palo Alto NGTS for enrolling a certificate where the certificate is not issued after two 
minutes and then subsequently retrieve that certificate after it has been issued:
```
vcert enroll -p ngts -t eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... -z "Storefront\\Public Trust" --no-prompt --cn demo-pickup.venafi.example

vcert pickup -p ngts -t eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... --pickup-id "{7428fac3-d0e8-4679-9f48-d9e867a326ca}"
```

Submit request to Palo Alto NGTS for enrolling a certificate that will be retrieved later using a Pickup ID from 
a text file:
```
vcert enroll -p ngts -t eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... -z "Storefront\\Public Trust" --no-prompt --cn demo-pickup.venafi.example --no-pickup -pickup-id-file pickup_id.txt

vcert pickup -p ngts -t eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... --pickup-id-file pickup_id.txt
```

Submit request to Palo Alto NGTS for renewing a certificate using the enrollment (pickup) ID of the expiring 
certificate:
```
vcert renew -p ngts -t eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... --id "{7428fac3-d0e8-4679-9f48-d9e867a326ca}"
```

Submit request to Palo Alto NGTS for renewing a certificate using the expiring certificate file:
```
vcert renew -p ngts -t eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... --thumbprint file:/opt/pki/demo.crt
```

## Appendix

### Obtaining an Access Token

You can obtain an access token using service account credentials:

```
vcert getcred -p ngts --token-url <token url> --client-id <client id> --client-secret <client secret> --scope <scope>
```

Options:

| Flag               | Description                                                                                                   |
|--------------------|---------------------------------------------------------------------------------------------------------------|
| `-p` or `--platform` | Use to specify Palo Alto Networks NGTS as the platform. Accepted value is `ngts`, case-insensitive.          |
| `--token-url`      | The URL used to obtain the access token, provided by Palo Alto NGTS's service account configuration           |
| `--client-id`      | The Client ID of the service account that will be used to obtain the access token                             |
| `--client-secret`  | The Client Secret of the service account that will be used to obtain the access token                         |
| `--scope`          | The scope(s) requested for the access token                                                                    |

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