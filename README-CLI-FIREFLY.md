[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & Cloud](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20Cloud-f9a90c)  
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# VCert CLI for CyberArk Workload Identity Manager

_CyberArk VCert_ is a command line tool designed to generate keys and simplify certificate acquisition, eliminating the need to write code that's required to interact with the CyberArk REST API. _VCert_ is available in 32- and 64-bit versions for Linux, Windows, and macOS.

This article applies to the latest version of _VCert CLI_, which you can [download here](https://github.com/Venafi/vcert/releases/latest).

On macOS and Linux, if you have [Homebrew](https://brew.sh) you can install VCert with:

```shell
brew install venafi/tap/vcert
```

## Quick Links

Use these to quickly jump to a relevant section lower on this page:

- [VCert CLI for CyberArk Workload Identity Manager](#vcert-cli-for-cyberark-workload-identity-manager)
  - [Quick Links](#quick-links)
  - [Prerequisites](#prerequisites)
    - [Compatibility](#compatibility)
  - [Command Line Actions](#command-line-actions)
    - [Environment Variables](#environment-variables)
  - [Certificate Request Parameters](#certificate-request-parameters)
  - [Examples](#examples)
  - [Appendix](#appendix)
    - [Obtaining an Authorization Token](#obtaining-an-authorization-token)
      - [Client credentials flow grant parameters](#client-credentials-flow-grant-parameters)
      - [Device code flow grant parameters](#device-code-flow-grant-parameters)
      - [Resource owner password credentials flow grant parameters](#resource-owner-password-credentials-flow-grant-parameters)
    - [Generating a new key pair and CSR](#generating-a-new-key-pair-and-csr)

## Prerequisites

Review these prerequisites to get started. You'll need: 

1. An **identity provider** with support for [OAuth 2.0](https://oauth.net/2/) configured to manage at least one of the following [OAuth 2.0 grant types](https://oauth.net/2/grant-types/): [client credentials](https://oauth.net/2/grant-types/client-credentials/), [device code](https://oauth.net/2/grant-types/device-code/) and [resource owner password credentials](https://oauth.net/2/grant-types/password/).
2. A [CyberArk Workload Identity Manager](https://venafi.com/firefly/) environment with the following requirements ([see here](https://developer.venafi.com/tlsprotectcloud/docs/firefly) for more details):
   1. Configured the [TLS server interface for rest](https://developer.venafi.com/tlsprotectcloud/docs/firefly-config-yaml-reference#server-section).
   2. Additionally, for _CyberArk Workload Identity Manager developer mode_ it's required to have configured the [authentication/authorization](https://developer.venafi.com/tlsprotectcloud/docs/firefly-config-yaml-reference#server-section) section to validate the [JSON Web Tokens](https://jwt.io/) provided by the _identity provider_.

### Compatibility

**[VCert 5.1](https://github.com/Venafi/vcert/releases/tag/v5.1)** and later versions are compatible with **CyberArk Workload Identity Manager**.

## Command Line actions

_VCert CLI_ for _CyberArk Workload Identity Manager_ provides support for `getcred`([see in appendix](#obtaining-an-authorization-token)) and `enroll` actions.


### Environment Variables

As an alternative to specifying a `platform`, `token`, `trust bundle`, `url`, and/or `zone` via the command line or in a config file, _VCert_ supports supplying those values using environment variables `VCERT_PLATFORM`, `VCERT_TOKEN`, `VCERT_TRUST_BUNDLE`, `VCERT_URL`, and `VCERT_ZONE` respectively.

## Certificate Request Parameters

To request a certificate to _CyberArk Workload Identity Manager_, _VCert CLI_ provides the `enroll` action.

Example
```
vcert enroll -u <CyberArk Workload Identity Manager ip/url> -t <auth token> --cn <common name> -z <policy name>
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                                                                                                                                                                                                                                                                                                                                   |
|---------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--app-info`                                                                                            | Use to identify the application requesting the certificate with details like vendor name and vendor product.<br/>Example: `--app-info "CyberArk VCert CLI"`                                                                                                                                                                                                                   |
| `--cert-file`                                                                                           | Use to specify the name and location of an output file that will contain only the end-entity certificate.<br/>Example: `--cert-file /path-to/example.crt`                                                                                                                                                                                                                     |
| `--chain`                                                                                               | Use to include the certificate chain in the output, and to specify where to place it in the file.<br/>Options: `root-last` (default), `root-first`, `ignore`                                                                                                                                                                                                                  |
| `--chain-file`                                                                                          | Use to specify the name and location of an output file that will contain only the root and intermediate certificates applicable to the end-entity certificate.                                                                                                                                                                                                                |
| `--cn`                                                                                                  | Use to specify the common name (CN). This is required for Enrollment.                                                                                                                                                                                                                                                                                                         |
| `--csr`                                                                                                 | Use to specify the CSR and private key location. Options: `local` (default), `service`, `file`<br/>- local: private key and CSR will be generated locally<br/>- service: private key and CSR will be generated within CyberArk Workload Identity Manager<br/>- file: CSR will be read from a file by name<br/>Example: `--csr file:/path-to/example.req`                      |
| `--field`                                                                                               | Use to specify Custom Fields in 'key=value' format. If many values are required for the same Custom Field (key), use the following syntax: `--field key1=value1` `--field key1=value2` ...                                                                                                                                                                                    |
| `--file`                                                                                                | Use to specify a name and location of an output file that will contain the private key and certificates when they are not written to their own files using `--key-file`, `--cert-file`, and/or `--chain-file`.<br/>Example: `--file /path-to/keycert.pem`                                                                                                                     |
| `--format`                                                                                              | Use to specify the output format.  The `--file` option must be used with the PKCS#12 and JKS formats to specify the keystore file. JKS format also requires `--jks-alias` and at least one password (see `--key-password` and `--jks-password`) <br/>Options: `pem` (default), `legacy-pem`, `json`, `pkcs12`, `legacy-pkcs12` (analogous to OpenSSL 3.x -legacy flag), `jks` |
| `--instance`                                                                                            | Use to provide the name/address of the compute instance and an identifier for the workload using the certificate. This results in a device (node) and application (workload) being associated with the certificate in the CyberArk Workload Identity Manager.<br/>Example: `--instance node:workload`                                                                         |
| `--jks-alias`                                                                                           | Use to specify the alias of the entry in the JKS file when `--format jks` is used                                                                                                                                                                                                                                                                                             |
| `--jks-password`                                                                                        | Use to specify the keystore password of the JKS file when `--format jks` is used.  If not specified, the `--key-password` value is used for both the key and store passwords                                                                                                                                                                                                  |
| `--key-curve`                                                                                           | Use to specify the elliptic curve for key generation when `--key-type` is ECDSA.<br/>Options: `p256` (default), `p384`, `p521`                                                                                                                                                                                                                                                |
| `--key-file`                                                                                            | Use to specify the name and location of an output file that will contain only the private key.<br/>Example: `--key-file /path-to/example.key`                                                                                                                                                                                                                                 |
| `--key-password`                                                                                        | Use to specify a password for encrypting the private key. For a non-encrypted private key, specify `--no-prompt` without specifying this option. You can specify the password using one of three methods: at the command line, when prompted, or by using a password file.<br/>Example: `--key-password file:/path-to/passwd.txt`                                             |
| `--key-size`                                                                                            | Use to specify a key size for RSA keys.  Default is 2048.                                                                                                                                                                                                                                                                                                                     |
| `--key-type`                                                                                            | Use to specify the key algorithm.<br/>Options: `rsa` (default), `ecdsa`                                                                                                                                                                                                                                                                                                       |
| `--nickname`                                                                                            | Use to specify a name for the new certificate object that will be created and placed in a folder (which you specify using the `-z` option).                                                                                                                                                                                                                                   |
| `--no-pickup`                                                                                           | Use to disable the feature of VCert that repeatedly tries to retrieve the issued certificate.  When this is used you must run VCert again in pickup mode to retrieve the certificate that was requested.                                                                                                                                                                      |
| `--pickup-id-file`                                                                                      | Use to specify a file name where the unique identifier for the certificate will be stored for subsequent use by pickup, renew, and revoke actions.  Default is to write the Pickup ID to STDOUT.                                                                                                                                                                              |
| `--platform`                                                                                            | (REQUIRED) Use to specify the CyberArk Workload Identity Manager platform.<br/>Example: `--platform firefly`                                                                                                                                                                                                                                                                  |
| `--replace-instance`                                                                                    | Force the specified instance to be recreated if it already exists and is associated with the requested certificate.  Default is for the request to fail if the instance already exists.                                                                                                                                                                                       |
| `--san-dns`                                                                                             | Use to specify a DNS Subject Alternative Name. To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-dns one.example.com` `--san-dns two.example.com`                                                                                                                                                                                    |
| `--san-email`                                                                                           | Use to specify an Email Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-email me@example.com` `--san-email you@example.com`                                                                                                                                                                             |
| `--san-ip`                                                                                              | Use to specify an IP Address Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-ip 10.20.30.40` `--san-ip 192.168.192.168`                                                                                                                                                                                 |
| `--tls-address`                                                                                         | Use to specify the hostname, FQDN or IP address and TCP port where the certificate can be validated after issuance and installation. Only allowed when `--instance` is also specified.<br/>Example: `--tls-address 10.20.30.40:443`                                                                                                                                           |
| `-u`                                                                                                    | Use to specify the URL of the CyberArk Workload Identity Manager API server.<br/>Example: `-u https://firefly.venafi.example`                                                                                                                                                                                                                                                 |
| `--valid-days`                                                                                          | Use to specify the number of days a certificate needs to be valid if supported/allowed by the CA template. Indicate the target issuer by appending #D for DigiCert, #E for Entrust, or #M for Microsoft.<br/>Example: `--valid-days 90#M`<br/> Note: You can use the `valid-period` flag instead of this.                                                                     |
| `--valid-period`                                                                                        | Use to specify the validity period certificate needs to be valid expressed as an ISO 8601 duration. This parameter has precedence over `valid-days` parameter.                                                                                                                                                                                                                |
| `-z`                                                                                                    | Use to specify the policy name configured in _CyberArk Workload Identity Manager_.<br/>Example: `-z "my policy"`                                                                                                                                                                                                                                                              |


## Examples

For the purposes of the following examples, assume the following:

- The CyberArk Workload Identity Manager REST API is available at https://firefly.venafi.example:8003. 
- An OAuth 2.0 access token with value "ql8AEpCtGSv61XGfAknXIA==..." and scope of "certificate:create" was gotten. 
- CyberArk Workload Identity Manager was configured with a policy called _DevOps Certificates_. along with other typical policy settings (such as, organization, city, state, country, key size, whitelisted domains, etc.).

Use the Help to view the command line syntax for enroll:
```
vcert enroll -h
```
Submit a CyberArk Workload Identity Manager request for enrolling a certificate with a common name of “first-time.venafi.example” using an authentication token and have VCert prompt for the password to encrypt the private key:
```
vcert enroll --platform firefly -u https://firefly.venafi.example:8003 -t "ql8AEpCtGSv61XGfAknXIA==..." -z "DevOps Certificates" --cn first-time.venafi.example
```
Submit a CyberArk Workload Identity Manager request for enrolling a certificate where the private key to be generated is not password encrypted:
```
vcert enroll --platform firefly -u https://firefly.venafi.example:8003 -t "ql8AEpCtGSv61XGfAknXIA==..." -z "DevOps Certificates" --cn non-encrypted-key.venafi.example --no-prompt
```
Submit a CyberArk Workload Identity Manager request for enrolling a certificate where the private key and CSR are to be generated by the CyberArk Workload Identity Manager:
```
vcert enroll --platform firefly -u https://firefly.venafi.example:8003 -t "ql8AEpCtGSv61XGfAknXIA==..." -z "DevOps Certificates" --cn service-generated.venafi.example --csr service --key-password somePassw0rd!
```
Submit a CyberArk Workload Identity Manager request for enrolling a certificate using an externally generated CSR:
```
vcert enroll --platform firefly -u https://firefly.venafi.example:8003 -t "ql8AEpCtGSv61XGfAknXIA==..." -z "DevOps Certificates" --nickname externally-generated-csr --csr file:/opt/pki/cert.req
```
Submit a CyberArk Workload Identity Manager request for enrolling a certificate where the certificate and private key are output using JSON syntax to a file called json.txt:
```
vcert enroll --platform firefly -u https://firefly.venafi.example:8003 -t "ql8AEpCtGSv61XGfAknXIA==..." -z "DevOps Certificates" --key-password Passw0rd --cn json-to-file.venafi.example --format json --file keycert.json
```
Submit a CyberArk Workload Identity Manager request for enrolling a certificate where only the certificate and private key are output, no chain certificates:
```
vcert enroll --platform firefly -u https://firefly.venafi.example:8003 -t "ql8AEpCtGSv61XGfAknXIA==..." -z "DevOps Certificates" --key-password Passw0rd --cn no-chain.venafi.example --chain ignore
```
Submit a CyberArk Workload Identity Manager request for enrolling two certificate that have the same common name but are to be represented by distinct objects in TPP rather than having the first certificate be considered an older generation of the second:
```
vcert enroll --platform firefly -u https://firefly.venafi.example:8003 -t "ql8AEpCtGSv61XGfAknXIA==..." -z "DevOps Certificates" --key-password Passw0rd --cn same-cn.venafi.example --nickname same-cn-separate-object-1

vcert enroll --platform firefly -u https://firefly.venafi.example:8003 -t "ql8AEpCtGSv61XGfAknXIA==..." -z "DevOps Certificates" --key-password Passw0rd --cn same-cn.venafi.example --nickname same-cn-separate-object-2
```
Submit a CyberArk Workload Identity Manager request for enrolling a certificate with three subject alternative names, one each of DNS name, IP address, and email address:
```
vcert enroll --platform firefly -u https://firefly.venafi.example:8003 -t "ql8AEpCtGSv61XGfAknXIA==..." -z "DevOps Certificates" --no-prompt --cn three-san-types.venafi.example --san-dns demo.venafi.example --san-ip 10.20.30.40 --san-email zach.jackson@venafi.example
```


## Appendix

### Obtaining an Authorization Token

To get an authorization token, _VCert CLI_ provides the `getcred` action. This action allows to get an [OAuth 2.0 access token](https://oauth.net/2/access-tokens/) from an _identity provider_.

_VCert CLI_ for _CyberArk Workload Identity Manager_ supports three [OAuth 2.0 grant types](https://oauth.net/2/grant-types/): [client credentials](https://oauth.net/2/grant-types/client-credentials/), [device code](https://oauth.net/2/grant-types/device-code/) and [resource owner password credentials](https://oauth.net/2/grant-types/password/), so it's required to set one of these in order to use the _**get credentials action**_ successfully.

The following are common options independently of the _OAuth 2.0 grant type configured_:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                                                                                                                                                                                                                                            |
|---------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--audience`                                                                                            | Use to specify the _audience_. It's not part of OAuth 2.0 specification, but it's implemented by some _identity providers_.<br/>Example: `--audience http://my.audience`                                                                                                               |
| `--client-id`                                                                                           | (REQUIRED) Use to specify the _[client id](https://www.oauth.com/oauth2-servers/client-registration/client-id-secret/)_ registered in the OAuth provider.<br/>Example: `--client-id fkUdhCrIKIgTsJtCJZTNK5JPpXZ6UOuM`                                                                  |
| `--config`                                                                                              | Use to specify INI configuration file containing connection details. Available parameters: `oauth_token_url`, `oauth_client_id`, `oauth_client_secret`, `oauth_user`, `oauth_password`, `oauth_device_url`, `oauth_audience`, `oauth_scope`, `trust_bundle`, `test_mode`               |
| `--format`                                                                                              | Specify "json" to get JSON formatted output instead of the plain text default.                                                                                                                                                                                                         |
| `--no-prompt`                                                                                           | Use to exclude password prompts.  If you enable the prompt and you enter incorrect information, an error is displayed.  This option is useful with scripting.                                                                                                                          |
| `--platform`                                                                                            | (REQUIRED) Use to specify the CyberArk Workload Identity Manager. The value to set is 'oidc'.<br/>Example: `--platform oidc`                                                                                                                                                           |
| `--scope`                                                                                               | Use to specify the _[OAuth scope](https://oauth.net/2/scope/)_. Multiples scopes must be separated by `;`.<br/>Example: `--scope read:client_grants;offline_access`                                                                                                                    |
| `--test-mode`                                                                                           | Use to test operations without connecting to CyberArk Workload Identity Manager.  This option is useful for integration tests where the test environment does not have access to CyberArk Workload Identity Manager.  Default is false.                                                |
| `--test-mode-delay`                                                                                     | Use to specify the maximum number of seconds for the random test-mode connection delay.  Default is 15 (seconds).                                                                                                                                                                      |
| `--trust-bundle`                                                                                        | Use to specify a file with PEM formatted certificates to be used as trust anchors when communicating with CyberArk Workload Identity Manager. VCert uses the trust store of your operating system for this purpose if not specified.<br/>Example: `--trust-bundle /path-to/bundle.pem` |
| `-u`                                                                                                    | (REQUIRED) Use to specify the _OAuth token URL_ to request an access token.<br/>Example: `-u https://myauth0domain/oauth/token`                                                                                                                                                        |
| `--verbose`                                                                                             | Use to increase the level of logging detail, which is helpful when troubleshooting issues.                                                                                                                                                                                             |

### Client credentials flow grant parameters

The following is the required parameter needed to get credentials using the _OAuth 2.0 client credentials flow grant_:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                             |
|---------------------------------------------------------------------------------------------------------|---------------------------------------------------------|
| `--client-secret`                                                                                       | (REQUIRED) Use to specify the _OAuth 2.0 client secret_ |
Example
```
vcert getcred ---platform oidc -u <idp token url> --client-id <idp client id> --client-secret <idp client secret> --audience <idp audience> --scope <idp scopes> --format text
```

### Device code flow grant parameters

The following is the required parameter needed to get credentials using the non standard _OAuth 2.0 device code flow grant_:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                              |
|---------------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| `--device-url`                                                                                          | (REQUIRED) Use to specify the non _OAuth 2.0 device url_ |
Example
```
vcert getcred ---platform oidc -u <idp token url> --client-id <idp client id> --device-url <idp device url> --audience <idp audience> --scope <idp scopes> --format text
```

### Resource owner password credentials flow grant parameters

The following are the required parameters needed to get credentials using the _OAuth 2.0 resource owner password credentials flow grant_:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                               |
|---------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| `--username`                                                                                            | (REQUIRED) Use to specify the _OAuth 2.0 user's name_     |
| `--password`                                                                                            | (REQUIRED) Use to specify the _OAuth 2.0 user's password_ |
Example
```
vcert getcred ---platform oidc -u <idp token url> --client-id <idp client id> --username <idp username> --username <idp user's password> --audience <idp audience> --scope <idp scopes> --format text
```

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
