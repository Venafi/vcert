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
- [Options for requesting an SSH certificate using the `sshenroll` action](#ssh-certificate-request-parameters)
- [Options for downloading an SSH certificate using the `sshpickup` action](#ssh-certificate-retrieval-parameters)
- [Options for downloading an SSH CA's public key using the `sshgetconfig` action](#parameters-for-retrieving-an-ssh-cas-public-key)
- [Options for obtaining a new authorization token using the `getcred` action](#obtaining-an-authorization-token)
- [Options for checking the validity of an authorization token using the `checkcred` action](#checking-the-validity-of-an-authorization-token)
- [Options for invalidating an authorization token using the `voidcred` action](#invalidating-an-authorization-token)

## Prerequisites

Review these prerequistes to get started. You'll need: 

1. A user account that has an authentication token with "ssh:manage" scope (i.e. access to the "Venafi VCert CLI" API Application as of 21.2)
2. A folder where the user has been granted the following permissions: View, Read, Write, Create, and Private Key Read; this is for the pickup action when the certificate signing request (CSR) is service-generated.

### Compatibility

VCert is compatible with Trust Protection Platform 20.3 or later for SSH Certificates.

## General Command Line Parameters

The following options apply to the `sshenroll` and `sshpickup` actions:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ------------------- | ------------------------------------------------------------ |
| `--config`          | Use to specify INI configuration file containing connection details.  Available parameters:  *tpp_url*, *tpp_user*, *tpp_password*, *tpp_zone*, *trust_bundle*, *test_mode* |
| `--no-prompt`       | Use to exclude password prompts.  If you enable the prompt and you enter incorrect information, an error is displayed.  This option is useful with scripting. |
| `--t`               | Use to specify the token required to authenticate with Venafi Platform 20.1 (and higher).  See the [Appendix](#obtaining-an-authorization-token) for help using VCert to obtain a new authorization token. |
| `--test-mode`       | Use to test operations without connecting to Venafi Platform.  This option is useful for integration tests where the test environment does not have access to Venafi Platform.  Default is false. |
| `--test-mode-delay` | Use to specify the maximum number of seconds for the random test-mode connection delay.  Default is 15 (seconds). |
| `--timeout`         | Use to specify the maximum amount of time to wait in seconds for a certificate to be processed by Venafi Platform. Default is 120 (seconds). |
| `--trust-bundle`    | Use to specify a file with PEM formatted certificates to be used as trust anchors when communicating with Venafi Platform. VCert uses the trust store of your operating system for this purpose if not specified.<br/>Example: `--trust-bundle /path-to/bundle.pem` |
| `-u`                | Use to specify the URL of the Venafi Trust Protection Platform API server.<br/>Example: `-u https://tpp.venafi.example` |
| `--verbose`         | Use to increase the level of logging detail, which is helpful when troubleshooting issues. |

### Environment Variables

As an alternative to specifying a token, trust bundle, url, and/or zone via the command line or in a config file, VCert supports supplying those values using environment variables `VCERT_TOKEN`, `VCERT_TRUST_BUNDLE`, `VCERT_URL`, and `VCERT_ZONE` respectively.


## SSH Certificate Request Parameters
```
vcert sshenroll -u <tpp url> -t <auth token> --template <ssh ca> --id <cert id> --principal <user> --valid-hours 1
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `--destination-address`                                      | Use to specify the address (FQDN, hostname, IP address, or CIDR) of the destination host where the certificate will be used for authentication. Applicable for client certificates and is used for reporting/auditing only. |
| `--extension`                                                | Use to request certificate extensions. For basic extensions use `--extension <value>` and for key-value extensions use `--extension <key>:<value>` |
| `--folder`                                                   | Use to specify the DN of the policy folder within which the certificate object will be created. If not specified, the default policy folder indicated by the certificate template will be used. |
| `--force-command`                                            | Use to request a force command. Example: `--force-command "/usr/scripts/db_backup.sh"` |
| `--id`                                                       | Use to specify the identifier of the SSH certificate.  This is typically used to determine ownership. |
| `--key-passphrase`                                           | Use to specify the passphrase for encrypting the private key. |
| `--key-size`                                                 | Use to specify the key size in bits when creating a keypair using `--public-key local` |
| `--object-name`                                              | Use to specify a friendly name for the certificate object. If not specified, the value of the `--id` parameter is used. |
| `--principal`                                                | Use to specify principals for the certificate. If not specified, the default principals indicated by the certificate template will be used. |
| `--public-key`                                               | Use to specify the origin of the public key.  Options: `local` (default), `service`, or `file:/path-to/key.pub` |
| `--source-address`                                           | Use to specify the source addresses as list of IP addresses or CIDR. Example: `--source-address 192.168.1.1/24` |
| `--template`                                                 | Used to specify the SSH certificate issuing template that will be used to sign the certificate. |
| `--valid-hours`                                              | Use to specify the number of hours a certificate needs to be valid. |
| `--windows`                                                  | Output certificate and key files in Windows format (i.e. with \r\n line endings) instead of Unix format (i.e. \n line endings). |


## SSH Certificate Retrieval Parameters
```
vcert sshpickup -u <tpp url> -t <auth token> --pickup-id <cert DN>
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `--guid`                                                     | Use to specify the identifier of the SSH certificate to retrieve (alternative to specifying the SSH certificate by DN using `--pickup-id`). |
| `--key-passphrase`                                           | Use to specify the passphrase for encrypting the private key. |
| `--pickup-id`                                                | Use to specify the DN of the SSH certificate to retrieve.    |
| `--windows`                                                  | Output certificate and key files in Windows format (i.e. with \r\n line endings) instead of Unix format (i.e. \n line endings). |


## Parameters for retrieving an SSH CA's public key
```
vcert sshgetconfig -u <tpp url> -t <auth token> --template <ssh ca>
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `--file`                                                     | Use to specify the file to which the SSH CA public key will be written. Example: `--file /path-to/ssh_ca.pub` |
| `--guid`                                                     | Use to specify the identifier of the SSH certificate issuing template to view (alternative to specifying the issuing template by DN using `--template`). |
| `--template`                                                 | Use to specify the DN of the SSH certificate issuing template to view. |


## Examples

For the purposes of the following examples, assume the following:

- The Trust Protection Platform REST API is available at https://tpp.venafi.example/vedsdk 
- A user account named _SshCertSvc_ has been created with an authentication token of "ql8AEpCtGSv61XGfAknXIA==", with a scope of "ssh:manage". 
- A folder structure has been created at the root of the Policy Tree called _ssh-certificates\dev-db-admins_ and the *SshCertSvc* user has been granted View, Read, Write, Create, and Private Key Read permissions to that folder.  
- An SSH Certificate Issuing Template has been created called _DB-Admins-Template_.

Use the Help to view the command line syntax for enroll:
```
vcert enroll -h
```
Submit a Trust Protection Platform request for enrolling an SSH certificate from the SSH Certificate Issuing Template for the db-admin, to access a computer for 8 hours:  
```
vcert sshenroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --template DB-Admins-Template --id example-certificate --principal db-admin --valid-hours 8
```
Submit a Trust Protection Platform request for enrolling an SSH certificate with multiple principals for 8 hours:
```
vcert sshenroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --template DB-Admins-Template --id example-certificate --principal db-admin --principal db-user --valid-hours 8
```
Submit a Trust Protection Platform request for enrolling an SSH certificate with a different object name on TPP:
```
vcert sshenroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --template DB-Admins-Template --id example-certificate --principal db-admin --object-name "DB-admin-certificate" 
```
Submit a Trust Protection Platform request for enrolling an SSH certificate with extensions:
```
vcert sshenroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --template DB-Admins-Template --id example-certificate --principal db-admin --extension "permit-pty" --extension "permit-port-forwarding" 
```
Submit a Trust Protection Platform request for enrolling an SSH certificate with a custom extension:
```
vcert sshenroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --template DB-Admins-Template --id example-certificate --principal db-admin --extension "login@github.com":"alice@github.com"
```
Submit a Trust Protection Platform request for enrolling an SSH certificate with source addresses where one is an IP the other is CIDR:
```
vcert sshenroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --template DB-Admins-Template --id example-certificate "192.168.2.73"  --source-address "192.168.1.0/24"
```
Submit a Trust Protection Platform request for enrolling an SSH certificate with the private key to be generated and stored in Trusted Protect Platform:
```
vcert sshenroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --template DB-Admins-Template --id example-certificate --public-key "service"
```
Submit a Trust Protection Platform request for enrolling an SSH certificate using a pre-existing SSH public key:
```
vcert sshenroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --template DB-Admins-Template --id example-certificate --public-key "file:/home/db-user/.ssh/id_rsa.pub" 
```
Submit a Trust Protection Platform request for enrolling an SSH certificate with a specific key size and a non-default policy folder:
```
vcert sshenroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --template DB-Admins-Template --id example-certificate --key-size 4096 --folder "\VED\Policy\ssh-certificates\dev-db-admins"
```
Submit a Trust Protection Platform request for enrolling an SSH certificate with forced command:
```
vcert sshenroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --template DB-Admins-Template --id example-certificate --force-command "./home/db-user/scripts/configure.sh"
```
Submit a Trust Protection Platform request for enrolling an SSH certificate without any credential or password prompts:
```
vcert sshenroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --template DB-Admins-Template --id example-certificate --no-prompt
```
Submit a Trust Protection Platform request for enrolling an SSH certificate with a passphrase encrypted private key and for the private key file to use Windows line endings:
```
vcert sshenroll -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --template DB-Admins-Template --id example-certificate --key-passphrase "MyPassword" --windows
```
Submit a Trust Protection Platform request for retrieving an SSH certificate by its object DN:
```
vcert sshpickup -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --pickup-id "\VED\Policy\ssh-certificates\dev-db-admins\example-certificate"
```
Submit a Trust Protection Platform request for retrieving an SSH certificate by its object GUID:
```
vcert sshpickup -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --guid "{855bbf35-b098-412d-b45a-2091f8c653c8}"
```
Submit a Trust Protection Platform request for retrieving an SSH certificate without any credential or password prompts:
```
vcert sshpickup -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --pickup-id "\VED\Policy\ssh-certificates\dev-db-admins\example-certificate" --no-prompt
```
Submit a Trust Protection Platform request for retrieving an SSH certificate with a passphrase encrypted private key and for the private key file to use Windows line endings:
```
vcert sshpickup -u https://tpp.venafi.example -t "ql8AEpCtGSv61XGfAknXIA==" --guid "{855bbf35-b098-412d-b45a-2091f8c653c8}" --key-passphrase "MyPassword" --windows
```


## Appendix

### Obtaining an Authorization Token
```
vcert getcred -u <tpp url> --username <tpp username> --password <tpp password> --ssh

vcert getcred -u <tpp url> --p12-file <client cert file> --p12-password <client cert file password> --ssh
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| `--client-id`    | Use to specify the application that will be using the token. "vcert-cli" is the default. |
| `--format`       | Specify "json" to get JSON formatted output instead of the plain text default. |
| `--password`     | Use to specify the Venafi Platform user's password.          |
| `--p12-file`     | Use to specify a PKCS#12 file containing a client certificate (and private key) of a Venafi Platform user to be used for mutual TLS. Required if `--username` or `--t` is not present and may not be combined with either. Must specify `--trust-bundle` if the chain for the client certificate is not in the PKCS#12 file. |
| `--p12-password` | Use to specify the password of the PKCS#12 file containing the client certificate
| `--ssh`          | Use to request a token that can be used for ssh actions.  This is the equivalent of `--scope  ssh:manage;`|
| `--scope`        | Use to request specific scopes and restrictions. If not specified, tokens with the "certificate:manage,revoke;" scope are returned.  When requesting a token for ssh actions `--scope  ssh:manage;` is required or alternatively, the `--ssh` option can be specified.|
| `-t`             | Use to specify a refresh token for a Venafi Platform user. Required if `--username` or `--p12-file` is not present and may not be combined with either. |
| `--trust-bundle` | Use to specify a PEM file name to be used as trust anchors when communicating with the Venafi Platform API server. |
| `-u`             | Use to specify the URL of the Venafi Trust Protection Platform API server.<br/>Example: `-u https://tpp.venafi.example` |
| `--username`     | Use to specify the username of a Venafi Platform user. Required if `--p12-file` or `--t` is not present and may not be combined with either. |

### Checking the validity of an Authorization Token
![Minimum Patch Level: TPP 20.1.7+ and 20.2.2+](https://img.shields.io/badge/Minimum%20Patch%20Level-%20TPP%2020.1.7%20and%2020.2.2-f9a90c)
```
vcert checkcred -u <tpp url> -t <access token>
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| `--format`       | Specify "json" to get JSON formatted output instead of the plain text default. |
| `-t`             | Use to specify an access token for a Venafi Platform user. |
| `--trust-bundle` | Use to specify a PEM file name to be used as trust anchors when communicating with the Venafi Platform API server. |
| `-u`             | Use to specify the URL of the Venafi Trust Protection Platform API server.<br/>Example: `-u https://tpp.venafi.example` |

### Invalidating an Authorization Token
```
vcert voidcred -u <tpp url> -t <access token>
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| `-t`             | Use to specify an access token for a Venafi Platform user. |
| `--trust-bundle` | Use to specify a PEM file name to be used as trust anchors when communicating with the Venafi Platform API server. |
| `-u`             | Use to specify the URL of the Venafi Trust Protection Platform API server.<br/>Example: `-u https://tpp.venafi.example` |
