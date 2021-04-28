![Venafi](Venafi_logo.png)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & Cloud](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20Cloud-f9a90c)  
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# VCert CLI for Venafi Trust Protection Platform

Venafi VCert is a command line tool designed to generate keys and simplify certificate acquisition, eliminating the need to write code that's required to interact with the Venafi REST API. VCert is available in 32- and 64-bit versions for Linux, Windows, and macOS.

This article applies to the latest version of VCert CLI, which you can [download here](https://github.com/Venafi/vcert/releases/latest).

## Quick Links

Use these to quickly jump to a relevant section lower on this page:

- [Detailed usage examples](#examples)
- [Options for requesting a certificate using the `enroll` action](#certificate-request-parameters)
- [Options for downloading a certificate using the `pickup` action](#certificate-retrieval-parameters)
- [Options for renewing a certificate using the `renew` action](#certificate-renewal-parameters)
- [Options for revoking a certificate using the `revoke` action](#certificate-revocation-parameters)
- [Options common to the `enroll`, `pickup`, `renew`, and `revoke` actions](#general-command-line-parameters)
- [Options for obtaining a new authorization token using the `getcred` action](#obtaining-an-authorization-token)
- [Options for checking the validity of an authorization token using the `checkcred` action](#checking-the-validity-of-an-authorization-token)
- [Options for invalidating an authorization token using the `voidcred` action](#invalidating-an-authorization-token)
- [Options for applying certificate policy using the `setpolicy` action](#parameters-for-applying-certificate-policy)
- [Options for viewing certificate policy using the `getpolicy` action](#parameters-for-viewing-certificate-policy)
- [Options for generating a new key pair and CSR using the `gencsr` action (for manual enrollment)](#generating-a-new-key-pair-and-csr)

## Prerequisites

Review these prerequistes to get started. You'll need: 

1. A user account that has an authentication token with "certificate:manage,revoke" scope (i.e. access to the "Venafi VCert CLI" API Application as of 20.1) or has been granted WebSDK Access
2. A folder where the user has been granted the following permissions: View, Read, Write, Create, Revoke (for the revoke action), and Private Key Read; this is for the pickup action when the certificate signing request (CSR) is service-generated.
3. A policy applied to the folder that specifies the following:
    1. Subject DN values for Organizational Unit (OU), Organization (O), City/Locality (L), State/Province (ST) and Country (C)
    2. CA Template that Trust Protection Platform will use to enroll certificate requests submitted by VCert
    3. Management Type not locked, or locked to _Enrollment_
    4. CSR Generation not locked, or locked to _Service Generated CSR_
    5. Generate Key/CSR on Application not locked, or locked to _No_
    6. (Recommended) Disable Automatic Renewal set to _Yes_
    7. (Recommended) Key Bit Strength set to 2048 or higher
    8. (Recommended) Domain Whitelisting policy assigned appropriately

### Compatibility

VCert is compatible with Trust Protection Platform 17.3 or later. The Custom Fields and Instance Tracking features require 18.2 or later. Token Authentication requires 20.1 or later; for earlier versions, username/password authentication (deprecated) applies.

## General Command Line Parameters

The following options apply to the `enroll`, `pickup`, `renew`, and `revoke` actions:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ------------------- | ------------------------------------------------------------ |
| `--config`          | Use to specify INI configuration file containing connection details.  Available parameters:  *tpp_url*, *tpp_user*, *tpp_password*, *tpp_zone*, *trust_bundle*, *test_mode* |
| `--no-prompt`       | Use to exclude password prompts.  If you enable the prompt and you enter incorrect information, an error is displayed.  This option is useful with scripting. |
| `--t`               | Use to specify the token required to authenticate with Venafi Platform 20.1 (and higher).  See the [Appendix](#obtaining-an-authorization-token) for help using VCert to obtain a new authorization token. |
| `--test-mode`       | Use to test operations without connecting to Venafi Platform.  This option is useful for integration tests where the test environment does not have access to Venafi Platform.  Default is false. |
| `--test-mode-delay` | Use to specify the maximum number of seconds for the random test-mode connection delay.  Default is 15 (seconds). |
| `--timeout`         | Use to specify the maximum amount of time to wait in seconds for a certificate to be processed by Venafi Platform. Default is 120 (seconds). |
| `--tpp-password`    | **[DEPRECATED]** Use to specify the password required to authenticate with Venafi Platform.  Use `-t` instead for Venafi Platform 20.1 (and higher). |
| `--tpp-user`        | **[DEPRECATED]** Use to specify the username required to authenticate with Venafi Platform.  Use `-t` instead for Venafi Platform 20.1 (and higher). |
| `--trust-bundle`    | Use to specify a file with PEM formatted certificates to be used as trust anchors when communicating with Venafi Platform. VCert uses the trust store of your operating system for this purpose if not specified.<br/>Example: `--trust-bundle /path-to/bundle.pem` |
| `-u`                | Use to specify the URL of the Venafi Trust Protection Platform API server.<br/>Example: `-u https://tpp.venafi.example` |
| `--verbose`         | Use to increase the level of logging detail, which is helpful when troubleshooting issues. |

### Environment Variables

As an alternative to specifying a token, trust bundle, url, and/or zone via the command line or in a config file, VCert supports supplying those values using environment variables `VCERT_TOKEN`, `VCERT_TRUST_BUNDLE`, `VCERT_URL`, and `VCERT_ZONE` respectively.

## Certificate Request Parameters
```
VCert enroll -u <tpp url> -t <auth token> --cn <common name> -z <zone>

VCert enroll -u <tpp url> --tpp-user <username> --tpp-password <password> --cn <common name> -z <zone>
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| -------------------- | ------------------------------------------------------------ |
| `--app-info`         | Use to identify the application requesting the certificate with details like vendor name and vendor product.<br/>Example: `--app-info "Venafi VCert CLI"` |
| `--cert-file`        | Use to specify the name and location of an output file that will contain only the end-entity certificate.<br/>Example: `--cert-file /path-to/example.crt` |
| `--chain`            | Use to include the certificate chain in the output, and to specify where to place it in the file.<br/>Options: `root-last` (default), `root-first`, `ignore` |
| `--chain-file`       | Use to specify the name and location of an output file that will contain only the root and intermediate certificates applicable to the end-entity certificate. |
| `--cn`               | Use to specify the common name (CN). This is required for Enrollment. |
| `--csr`              | Use to specify the CSR and private key location. Options: `local` (default), `service`, `file`<br/>- local: private key and CSR will be generated locally<br/>- service: private key and CSR will be generated within Venafi Platform<br/>- file: CSR will be read from a file by name<br/>Example: `--csr file:/path-to/example.req` |
| `--field`            | Use to specify Custom Fields in 'key=value' format. If many values are required for the same Custom Field (key), use the following syntax: `--field key1=value1` `--field key1=value2` ... |
| `--file`             | Use to specify a name and location of an output file that will contain the private key and certificates when they are not written to their own files using `--key-file`, `--cert-file`, and/or `--chain-file`.<br/>Example: `--file /path-to/keycert.pem` |
| `--format`         | Use to specify the output format.  The `--file` option must be used with the PKCS#12 and JKS formats to specify the keystore file. JKS format also requires `--jks-alias` and at least one password (see `--key-password` and `--jks-password`) <br/>Options: `pem` (default), `json`, `pkcs12`, `jks` |
| `--instance`         | Use to provide the name/address of the compute instance and an identifier for the workload using the certificate. This results in a device (node) and application (workload) being associated with the certificate in the Venafi Platform.<br/>Example: `--instance node:workload` |
| `--jks-alias`        | Use to specify the alias of the entry in the JKS file when `--format jks` is used |
| `--jks-password`     | Use to specify the keystore password of the JKS file when `--format jks` is used.  If not specified, the `--key-password` value is used for both the key and store passwords |
| `--key-curve`        | Use to specify the elliptic curve for key generation when `--key-type` is ECDSA.<br/>Options: `p256` (default), `p384`, `p521` |
| `--key-file`         | Use to specify the name and location of an output file that will contain only the private key.<br/>Example: `--key-file /path-to/example.key` |
| `--key-password`     | Use to specify a password for encrypting the private key. For a non-encrypted private key, specify `--no-prompt` without specifying this option. You can specify the password using one of three methods: at the command line, when prompted, or by using a password file.<br/>Example: `--key-password file:/path-to/passwd.txt` |
| `--key-size`         | Use to specify a key size for RSA keys.  Default is 2048.    |
| `--key-type`         | Use to specify the key algorithm.<br/>Options: `rsa` (default), `ecdsa` |
| `--nickname`         | Use to specify a name for the new certificate object that will be created and placed in a folder (which you specify using the `-z` option). |
| `--no-pickup`        | Use to disable the feature of VCert that repeatedly tries to retrieve the issued certificate.  When this is used you must run VCert again in pickup mode to retrieve the certificate that was requested. |
| `--pickup-id-file`   | Use to specify a file name where the unique identifier for the certificate will be stored for subsequent use by pickup, renew, and revoke actions.  Default is to write the Pickup ID to STDOUT. |
| `--replace-instance` | Force the specified instance to be recreated if it already exists and is associated with the requested certificate.  Default is for the request to fail if the instance already exists. |
| `--san-dns`          | Use to specify a DNS Subject Alternative Name. To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-dns one.example.com` `--san-dns two.example.com` |
| `--san-email`        | Use to specify an Email Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-email me@example.com` `--san-email you@example.com` |
| `--san-ip`           | Use to specify an IP Address Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-ip 10.20.30.40` `--san-ip 192.168.192.168` |
| `--tls-address`      | Use to specify the hostname, FQDN or IP address and TCP port where the certificate can be validated after issuance and installation. Only allowed when `--instance` is also specified.<br/>Example: `--tls-address 10.20.30.40:443` |
| `--valid-days`       | Use to specify the number of days a certificate needs to be valid if supported/allowed by the CA template. Indicate the target issuer by appending #D for DigiCert, #E for Entrust, or #M for Microsoft.<br/>Example: `--valid-days 90#M` |
| `-z`                 | Use to specify the folder path where the certificate object will be placed. VCert prepends \VED\Policy\, so you only need to specify child folders under the root Policy folder.<br/>Example: `-z DevOps\CorpApp` |

## Certificate Retrieval Parameters
```
VCert pickup -u <tpp url> -t <auth token> [--pickup-id <request id> | --pickup-id-file <file name>]

VCert pickup -u <tpp url> --tpp-user <username> --tpp-password <password> [--pickup-id <request id> | --pickup-id-file <file name>]
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ------------------ | ------------------------------------------------------------ |
| `--cert-file`      | Use to specify the name and location of an output file that will contain only the end-entity certificate.<br/>Example: `--cert-file /path-to/example.crt` |
| `--chain`          | Use to include the certificate chain in the output, and to specify where to place it in the file.<br/>Options:  `root-last` (default), `root-first`, `ignore` |
| `--chain-file`     | Use to specify the name and location of an output file that will contain only the root and intermediate certificates applicable to the end-entity certificate. |
| `--file`           | Use to specify a name and location of an output file that will contain certificates when they are not written to their own files using `--cert-file` and/or `--chain-file`.<br/>Example: `--file /path-to/keycert.pem` |
| `--format`         | Use to specify the output format.  The `--file` option must be used with the PKCS#12 and JKS formats to specify the keystore file. JKS format also requires `--jks-alias` and at least one password (see `--key-password` and `--jks-password`) <br/>Options: `pem` (default), `json`, `pkcs12`, `jks` |
| `--jks-alias`        | Use to specify the alias of the entry in the JKS file when `--format jks` is used |
| `--jks-password`     | Use to specify the keystore password of the JKS file when `--format jks` is used.  If not specified, the `--key-password` value is used for both the key and store passwords |
| `--pickup-id`      | Use to specify the unique identifier of the certificate returned by the enroll or renew actions if `--no-pickup` was used or a timeout occurred. Required when `--pickup-id-file` is not specified. |
| `--pickup-id-file` | Use to specify a file name that contains the unique identifier of the certificate returned by the enroll or renew actions if --no-pickup was used or a timeout occurred. Required when `--pickup-id` is not specified. |


## Certificate Renewal Parameters
```
VCert renew -u <tpp url> -t <auth token> [--id <request id> | --thumbprint <sha1 thumb>]

VCert renew -u <tpp url> --tpp-user <username> --tpp-password <password> [--id <request id> | --thumbprint <sha1 thumb>]
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ------------------ | ------------------------------------------------------------ |
| `--cert-file`      | Use to specify the name and location of an output file that will contain only the end-entity certificate.<br/>Example: `--cert-file /path-to/example.crt` |
| `--chain`          | Use to include the certificate chain in the output, and to specify where to place it in the file.<br/>Options: `root-last` (default), `root-first`, `ignore` |
| `--chain-file`     | Use to specify the name and location of an output file that will contain only the root and intermediate certificates applicable to the end-entity certificate. |
| `--cn`             | Use to specify the common name (CN). This is required for Enrollment. |
| `--csr`            | Use to specify the CSR and private key location. Options: `local` (default), `service`, `file`<br />- local: private key and CSR will be generated locally<br />- service: private key and CSR will be generated within Venafi Platform. Depending on policy, the private key may be reused<br />- file: CSR will be read from a file by name<br />Example: `--csr file:/path-to/example.req` |
| `--file`           | Use to specify a name and location of an output file that will contain the private key and certificates when they are not written to their own files using `--key-file`, `--cert-file`, and/or `--chain-file`.<br/>Example: `--file /path-to/keycert.pem` |
| `--format`         | Use to specify the output format.  The `--file` option must be used with the PKCS#12 and JKS formats to specify the keystore file. JKS format also requires `--jks-alias` and at least one password (see `--key-password` and `--jks-password`) <br/>Options: `pem` (default), `json`, `pkcs12`, `jks` |
| `--id`             | Use to specify the unique identifier of the certificate returned by the enroll or renew actions.  Value may be specified as a string or read from a file by using the file: prefix.<br/>Example: `--id file:cert_id.txt` |
| `--jks-alias`        | Use to specify the alias of the entry in the JKS file when `--format jks` is used |
| `--jks-password`     | Use to specify the keystore password of the JKS file when `--format jks` is used.  If not specified, the `--key-password` value is used for both the key and store passwords |
| `--key-curve`      | Use to specify the elliptic curve for key generation when `--key-type` is ECDSA.<br/>Options: `p256` (default), `p384`, `p521` |
| `--key-file`       | Use to specify the name and location of an output file that will contain only the private key.<br/>Example: `--key-file /path-to/example.key` |
| `--key-password`   | Use to specify a password for encrypting the private key. For a non-encrypted private key, specify `--no-prompt` without specifying this option. You can specify the password using one of three methods: at the command line, when prompted, or by using a password file. |
| `--key-size`       | Use to specify a key size for RSA keys. Default is 2048.     |
| `--key-type`       | Use to specify the key algorithm.<br/>Options: `rsa` (default), `ecdsa` |
| `--no-pickup`      | Use to disable the feature of VCert that repeatedly tries to retrieve the issued certificate.  When this is used you must run VCert again in pickup mode to retrieve the certificate that was requested. |
| `--omit-sans`      | Ignore SANs in the previous certificate when preparing the renewal request. Workaround for CAs that forbid any SANs even when the SANs match those the CA automatically adds to the issued certificate. |
| `--pickup-id-file` | Use to specify a file name where the unique identifier for the certificate will be stored for subsequent use by `pickup`, `renew`, and `revoke` actions.  By default it is written to STDOUT. |
| `--san-dns`          | Use to specify a DNS Subject Alternative Name. To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-dns one.example.com` `--san-dns two.example.com` |
| `--san-email`        | Use to specify an Email Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-email me@example.com` `--san-email you@example.com` |
| `--san-ip`           | Use to specify an IP Address Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-ip 10.20.30.40` `--san-ip 192.168.192.168` |
| `--thumbprint`     | Use to specify the SHA1 thumbprint of the certificate to renew. Value may be specified as a string or read from the certificate file using the `file:` prefix. |


## Certificate Revocation Parameters
```
VCert revoke -u <tpp url> -t <auth token> [--id <request id> | --thumbprint <sha1 thumb>]

VCert revoke -u <tpp url> --tpp-user <username> --tpp-password <password> [--id <request id> | --thumbprint <sha1 thumb>]
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| -------------- | ------------------------------------------------------------ |
| `--id`         | Use to specify the unique identifier of the certificate to revoke.  Value may be specified as a string or read from a file using the `file:` prefix. |
| `--no-retire`  | Do not disable certificate. Use this option if you intend to enroll a new version of the certificate later.  Works only with `--id` |
| `--reason`     | Use to specify the revocation reason.<br/>Options: `none` (default), `key-compromise`, `ca-compromise`, `affiliation-changed`, `superseded`, `cessation-of-operation` |
| `--thumbprint` | Use to specify the SHA1 thumbprint of the certificate to revoke. Value may be specified as a string or read from the certificate file using the `file:` prefix. |


## Parameters for Applying Certificate Policy
```
VCert setpolicy -u <tpp url> -t <auth token> -z <policy folder dn> --file <policy specification file>
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description |
| ------------------ | ------------------------------------------------------------ |
| `--file`           | Use to specify the location of the required file containing the certificate policy specification in JSON or YAML format. |
| `--verify`         | Use to verify that a policy specification is valid. `-k` and `-z` are ignored with this option. |

Notes:
- The `configuration:manage` scope (token auth) and `Manage Policy` permission are required to apply certificate policy.
- Policy and defaults revert to their default state if they are not present in a policy specification applied by this action.
- Policy and defaults will not override policy that is locked by a parent folder.
- If the policy folder specified by the `-z` zone parameter does not exist, this action will attempt to create it.
- This action can be used to simply create a new policy folder by indicating its name with the `-z` zone parameter and applying a file that contains an empty policy (i.e. `{}`).
- The syntax for the `certificateAuthority` policy value is the full object DN of an existing CA template (e.g. "\\VED\\Policy\\Certificate Authorities\\Entrust Advantage").
- The `maxValidDays` policy does not apply as validity in Trust Protection Platform is governed by the CA template.
- Although the `orgs`, `localities`, `states`, and `countries` policy (`subject`) are arrays, only a single value is allowed by Trust Protection Platform.
- Although the `keyTypes`, `rsaKeySizes`, and `ellipticCurves` policy (`keyPair`) are arrays, only a single value is allowed by Trust Protection Platform.
- The `autoInstalled` policy/default sets the _Management Type_ (i.e. `true`&#8594;Provisioning; `false`&#8594;Enrollment)
- The `serviceGenerated` policy/default sets the _CSR Generation_ (i.e. `true`&#8594;TPP generated; `false`&#8594;user provided)
- If undefined key/value pairs are included in the policy specification, they will be silently ignored by this action.  This would include keys that are misspelled.


## Parameters for Viewing Certificate Policy
```
VCert getpolicy -u <tpp url> -t <auth token> -z <policy folder dn> [--file <policy specification file>]
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description |
| ------------------ | ------------------------------------------------------------ |
| `--file`           | Use to write the retrieved certificate policy to a file in JSON format. If not specified, policy is written to STDOUT. |
| `--starter`        | Use to generate a template policy specification to help with getting started. `-k` and `-z` are ignored with this option. |


## Examples

For the purposes of the following examples, assume the following:

- The Trust Protection Platform REST API is available at https://tpp.venafi.example/vedsdk 
- A user account named _DevOps_ has been created with an authentication token of "ql8AEpCtGSv61XGfAknXIA==", with a scope of "certificate:manage,revoke", a password of "Passw0rd", and has been granted "WebSDK Access". 
- A folder has been created at the root of the Policy Tree called _DevOps Certificates_ and the DevOps user has been granted View, Read, Write, Create, Revoke, and Private Key Read permissions to that folder.  
- A CA Template has been created and assigned to the DevOps Certificates folder along with other typical policy settings (such as, organization, city, state, country, key size, whitelisted domains, etc.).

Use the Help to view the command line syntax for enroll:
```
VCert enroll -h
```
Submit a Trust Protection Platform request for enrolling a certificate with a common name of “first-time.venafi.example” using an authentication token and have VCert prompt for the password to encrypt the private key:
```
VCert enroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" -z "DevOps Certificates" --cn first-time.venafi.example
```
Submit a Trust Protection Platform request for enrolling a certificate with a common name of “first-time.venafi.example” and have VCert prompt for the DevOps user’s password and the password to encrypt the private key:
```
VCert enroll -u https://tpp.venafi.example --tpp-user DevOps -z "DevOps Certificates" --cn first-time.venafi.example
```
Submit a Trust Protection Platform request for enrolling a certificate where the DevOps user password is specified on the command line and the password for encrypting the private key to be generated is specified in a text file called passwd.txt:
```
VCert enroll -u https://tpp.venafi.example --tpp-user DevOps --tpp-password Passw0rd -z "DevOps Certificates" --key-password file:passwd.txt --cn passwd-from-file.venafi.example
```
Submit a Trust Protection Platform request for enrolling a certificate where the private key to be generated is not password encrypted:
```
VCert enroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" -z "DevOps Certificates" --cn non-encrypted-key.venafi.example --no-prompt
```
Submit a Trust Protection Platform request for enrolling a certificate where the private key and CSR are to be generated by the Venafi Platform:
```
VCert enroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" -z "DevOps Certificates" --cn service-generated.venafi.example --csr service --key-password somePassw0rd!
```
Submit a Trust Protection Platform request for enrolling a certificate using an externally generated CSR:
```
VCert enroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" -z "DevOps Certificates" --nickname externally-generated-csr --csr file:/opt/pki/cert.req
```
Submit a Trust Protection Platform request for enrolling a certificate where the certificate and private key are output using JSON syntax to a file called json.txt:
```
VCert enroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" -z "DevOps Certificates" --key-password Passw0rd --cn json-to-file.venafi.example --format json --file keycert.json
```
Submit a Trust Protection Platform request for enrolling a certificate where only the certificate and private key are output, no chain certificates:
```
VCert enroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" -z "DevOps Certificates" --key-password Passw0rd --cn no-chain.venafi.example --chain ignore
```
Submit a Trust Protection Platform request for enrolling two certificate that have the same common name but are to be represented by distinct objects in TPP rather than having the first certificate be considered an older generation of the second:
```
VCert enroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" -z "DevOps Certificates" --key-password Passw0rd --cn same-cn.venafi.example --nickname same-cn-separate-object-1

VCert enroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" -z "DevOps Certificates" --key-password Passw0rd --cn same-cn.venafi.example --nickname same-cn-separate-object-2
```
Submit a Trust Protection Platform request for enrolling a certificate with three subject alternative names, one each of DNS name, IP address, and email address:
```
VCert enroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" -z "DevOps Certificates" --no-prompt --cn three-san-types.venafi.example --san-dns demo.venafi.example --san-ip 10.20.30.40 --san-email zach.jackson@venafi.example
```
Submit a Trust Protection Platform request for enrolling a certificate and setting two Custom Fields, one string (Cost Center) and one multi-valued list (Environment):
```
VCert enroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" -z "DevOps Certificates" --no-prompt --cn custom-fields.venafi.example --field "Cost Center=ABC123" --field "Environment=Staging" --field "Environment=UAT"
```
Submit a Trust Protection Platform request for enrolling a certificate and identifying the location where it will be installed and can be validated:
```
VCert enroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" -z "DevOps Certificates" --no-prompt --cn custom-fields.venafi.example --instance beta-cluster.venafi.example:order_svc_23 --tls-address 10.20.30.40:44300
```
Submit a Trust Protection Platform request for enrolling a certificate where the certificate is not issued after two minutes and then subsequently retrieve that certificate after it has been issued:
```
VCert enroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" -z "DevOps Certificates" --no-prompt --cn demo-pickup.venafi.example

VCert pickup -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --pickup-id "\VED\Policy\DevOps Certificates\demo-pickup.venafi.example"
```
Note:  Special command line characters vary by shell will generally require escaping.  For example, in Unix/Linux shells the backslash character \ must be escaped so in the value of --pickup-id above would need to be "\\VED\\Policy\\DevOps Certificates\\demo-pickup.venafi.example".

Submit a Trust Protection Platform request for enrolling a certificate that will be retrieved later using a Pickup ID from in a text file:
```
VCert enroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" -z "DevOps Certificates" --no-prompt --cn demo-pickup.venafi.example --no-pickup -pickup-id-file pickup_id.txt

VCert pickup -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --pickup-id-file pickup_id.txt
```
Submit a Trust Protection Platform request for renewing a certificate using the enrollment (pickup) ID of the expiring certificate:
```
VCert renew -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --id "\VED\Policy\DevOps Certificates\demo.venafi.example"
```
Submit a Trust Protection Platform request for renewing a certificate using the expiring certificate file:
```
VCert renew -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --thumbprint file:/opt/pki/demo.crt
```
Submit a Trust Protection Platform revocation request using the enrollment (pickup) ID of the certificate and keep the certificate enabled so that a replacement certificate can be enrolled later:
```
VCert revoke -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --id "\VED\Policy\DevOps Certificates\demo.venafi.example" --reason superseded --no-retire
```
Submit a Trust Protection Platform revocation request using the actual certificate file:
```
VCert revoke -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --thumbprint file:/opt/pki/demo.crt --reason cessation-of-operation
```

## Appendix

### Obtaining an Authorization Token
```
VCert getcred -u <tpp url> --username <tpp username> --password <tpp password>

VCert getcred -u <tpp url> --p12-file <client cert file> --p12-password <client cert file password>
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| `--client-id`    | Use to specify the application that will be using the token. "vcert-cli" is the default. |
| `--format`       | Specify "json" to get JSON formatted output instead of the plain text default. |
| `--password`     | Use to specify the Venafi Platform user's password.          |
| `--p12-file`     | Use to specify a PKCS#12 file containing a client certificate (and private key) of a Venafi Platform user to be used for mutual TLS. Required if `--username` or `--t` is not present and may not be combined with either. Must specify `--trust-bundle` if the chain for the client certificate is not in the PKCS#12 file. |
| `--p12-password` | Use to specify the password of the PKCS#12 file containing the client certificate. |
| `--scope`        | Use to request specific scopes and restrictions. "certificate:manage,revoke;" is the default which is the minimum required to perform any actions supported by the VCert CLI. |
| `-t`             | Use to specify a refresh token for a Venafi Platform user. Required if `--username` or `--p12-file` is not present and may not be combined with either. |
| `--trust-bundle` | Use to specify a PEM file name to be used as trust anchors when communicating with the Venafi Platform API server. |
| `-u`             | Use to specify the URL of the Venafi Trust Protection Platform API server.<br/>Example: `-u https://tpp.example.com` |
| `--username`     | Use to specify the username of a Venafi Platform user. Required if `--p12-file` or `--t` is not present and may not be combined with either. |

### Checking the validity of an Authorization Token
![Minimum Patch Level: TPP 20.1.7+ and 20.2.2+](https://img.shields.io/badge/Minimum%20Patch%20Level-%20TPP%2020.1.7%20and%2020.2.2-f9a90c)
```
VCert checkcred -u <tpp url> -t <access token>
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| `--format`       | Specify "json" to get JSON formatted output instead of the plain text default. |
| `-t`             | Use to specify an access token for a Venafi Platform user. |
| `--trust-bundle` | Use to specify a PEM file name to be used as trust anchors when communicating with the Venafi Platform API server. |
| `-u`             | Use to specify the URL of the Venafi Trust Protection Platform API server.<br/>Example: `-u https://tpp.example.com` |

### Invalidating an Authorization Token
```
VCert voidcred -u <tpp url> -t <access token>
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| `-t`             | Use to specify an access token for a Venafi Platform user. |
| `--trust-bundle` | Use to specify a PEM file name to be used as trust anchors when communicating with the Venafi Platform API server. |
| `-u`             | Use to specify the URL of the Venafi Trust Protection Platform API server.<br/>Example: `-u https://tpp.example.com` |

### Generating a new key pair and CSR
```
vcert gencsr --cn <common name> -o <organization> --ou <ou1> --ou <ou2> -l <locality> --st <state> -c <country> --key-file <private key file> --csr-file <csr file>
```

Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| `-c` | Use to specify the country (C) for the Subject DN. |
| `--cn` | Use to specify the common name (CN). This is required for enrollment except when providing a CSR file. |
| `--csr-file` | Use to specify a file name and a location where the resulting CSR file should be written.<br/>Example: `--csr-file /path-to/example.req` |
| `--format` | Generates the Certificate Signing Request in the specified format. Options: `pem` (default), `json`<br />- pem: Generates the CSR in classic PEM format to be used as a file.<br />- json: Generates the CSR in JSON format, suitable for REST API operations. |
| `--key-curve` | Use to specify the ECDSA key curve. Options: `p256` (default), `p384`, `p521` |
| `--key-file` | Use to specify a file name and a location where the resulting private key file should be written. Do not use in combination with `--csr` file.<br/>Example: `--key-file /path-to/example.key` |
| `--key-password` | Use to specify a password for encrypting the private key. For a non-encrypted private key, omit this option and instead specify `--no-prompt`.<br/>Example: `--key-password file:/path-to/passwd.txt` |
| `--key-size` | Use to specify a key size.  Default is 2048. |
| `--key-type` | Use to specify a key type. Options: `rsa` (default), `ecdsa` |
| `-l` | Use to specify the city or locality (L) for the Subject DN. |
| `--no-prompt` | Use to suppress the private key password prompt and not encrypt the private key. |
| `-o` | Use to specify the organization (O) for the Subject DN. |
| `--ou` | Use to specify an organizational unit (OU) for the Subject DN. To specify more than one, simply repeat this parameter for each value.<br/>Example: `--ou "Engineering"` `--ou "Quality Assurance"` ... |
| `--san-dns`          | Use to specify a DNS Subject Alternative Name. To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-dns one.example.com` `--san-dns two.example.com` |
| `--san-email`        | Use to specify an Email Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-email me@example.com` `--san-email you@example.com` |
| `--san-ip`           | Use to specify an IP Address Subject Alternative Name.  To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-ip 10.20.30.40` `--san-ip 192.168.192.168` |
| `--st` | Use to specify the state or province (ST) for the Subject DN. |
