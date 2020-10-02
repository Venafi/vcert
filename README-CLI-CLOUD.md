![Venafi](Venafi_logo.png)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & Cloud](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20Cloud-f9a90c)  
_This open source project is community-supported. To report a problem or share an idea, use the
**[Issues](../../issues)** tab; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use the **[Pull requests](../../pulls)** tab to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions._

# VCert CLI for Venafi Cloud

Venafi VCert command line utility is designed to generate keys and simplify certificate acquisition by eliminating the need to write code to interact with the Venafi REST API. VCert is available in 32 and 64 bit versions for Linux, Windows, and macOS.

The following content applies to the latest version of VCert CLI, click [here](https://github.com/Venafi/vcert/releases/latest) to download it from https://github.com/Venafi/vcert/releases/latest.

## Quick Links
- [Detailed usage examples](#examples)
- [Options for requesting a certificate using the `enroll` action](#certificate-request-parameters)
- [Options for downloading a certificate using the `pickup` action](#certificate-retrieval-parameters)
- [Options for renewing a certificate using the `renew` action](#certificate-renewal-parameters)
- [Options common to the `enroll`, `pickup`, and `renew` actions](#general-command-line-parameters)
- [Options for generating a new key pair and CSR using the `gencsr` action (for manual enrollment)](#generating-a-new-key-pair-and-csr)

## Prerequisites

1. The Venafi Cloud REST API is accessible at https://api.venafi.cloud from the system where VCert will be executed.
2. You have successfully registered for a Venafi Cloud account, have been granted at least the "DevOps" role, and know your API key.
3. A CA Account and Issuing Template exist and have been configured with:
    1. Recommended Settings values for:
        1. Organizational Unit (OU)
        2. Organization (O)
        3. City/Locality (L)
        4. State/Province (ST)
        5. Country (C)
    2. Issuing Rules that:
        1. (Recommended) Limits Common Name and Subject Alternative Name to domains that are allowed by your organization
        2. (Recommended) Restricts the Key Length to 2048 or higher
        3. (Recommended) Does not allow Private Key Reuse
4. A DevOps Project exists to which you have been granted access.
5. A Zone has exists within the Project that uses the Issuing Template, and you know the Zone ID.

## General Command Line Parameters

The following options apply to the `enroll`, `pickup`, and `renew` actions:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ------------------- | ------------------------------------------------------------ |
| `--config`          | Use to specify INI configuration file containing connection details.  Available parameters: *cloud_apikey*, *cloud_zone*, *trust_bundle*, *test_mode* |
| `--k`               | Use to specify your API key for Venafi Cloud.<br/>Example: -k aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee |
| `--no-prompt`       | Use to exclude password prompts.  If you enable the prompt and you enter incorrect information, an error is displayed.  This option is useful with scripting. |
| `--test-mode`       | Use to test operations without connecting to Venafi Cloud.  This option is useful for integration tests where the test environment does not have access to Venafi Cloud.  Default is false. |
| `--test-mode-delay` | Use to specify the maximum number of seconds for the random test-mode connection delay.  Default is 15 (seconds). |
| `--timeout`         | Use to specify the maximum amount of time to wait in seconds for a certificate to be processed by Venafi Cloud. Default is 120 (seconds). |
| `--trust-bundle`    | Use to specify a file with PEM formatted certificates to be used as trust anchors when communicating with Venafi Cloud.  Generally not needed because Venafi Cloud is secured by a publicly trusted certificate but it may be needed if your organization requires VCert to traverse a proxy server. VCert uses the trust store of your operating system for this purpose if not specified.<br/>Example: `--trust-bundle /path-to/bundle.pem` |
| `--verbose`         | Use to increase the level of logging detail, which is helpful when troubleshooting issues. |

### Environment Variables

As an alternative to specifying API key, trust bundle, and/or zone via the command line or in a config file, VCert supports supplying those values using environment variables `VCERT_APIKEY`, `VCERT_TRUST_BUNDLE`, and `VCERT_ZONE` respectively.

## Certificate Request Parameters
```
VCert enroll -k <api key> --cn <common name> -z <zone id>
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| -------------------- | ------------------------------------------------------------ |
| `--app-info`         | Use to identify the application requesting the certificate with details like vendor name and vendor product.<br/>Example: `--app-info "Venafi VCert CLI"` |
| `--cert-file`        | Use to specify the name and location of an output file that will contain only the end-entity certificate.<br/>Example: `--cert-file /path-to/example.crt` |
| `--chain`            | Use to include the certificate chain in the output, and to specify where to place it in the file.<br/>Options: `root-last` (default), `root-first`, `ignore` |
| `--chain-file`       | Use to specify the name and location of an output file that will contain only the root and intermediate certificates applicable to the end-entity certificate. |
| `--cn`               | Use to specify the common name (CN). This is required for Enrollment. |
| `--csr`              | Use to specify the CSR and private key location. Options: `local` (default), `file`<br/>- local: private key and CSR will be generated locally<br/>- file: CSR will be read from a file by name<br/>Example: `--csr file:/path-to/example.req` |
| `--file`             | Use to specify a name and location of an output file that will contain the private key and certificates when they are not written to their own files using `--key-file`, `--cert-file`, and/or `--chain-file`.<br/>Example: `--file /path-to/keycert.pem` |
| `--format`         | Use to specify the output format.  The `--file` option must be used with the PKCS#12 format to specify the keystore file.<br/>Options: `pem` (default), `json`, `pkcs12` |
| `--key-file`         | Use to specify the name and location of an output file that will contain only the private key.<br/>Example: `--key-file /path-to/example.key` |
| `--key-password`     | Use to specify a password for encrypting the private key. For a non-encrypted private key, specify `--no-prompt` without specifying this option. You can specify the password using one of three methods: at the command line, when prompted, or by using a password file.<br/>Example: `--key-password file:/path-to/passwd.txt` |
| `--key-size`         | Use to specify a key size for RSA keys.  Default is 2048. |
| `--no-pickup`        | Use to disable the feature of VCert that repeatedly tries to retrieve the issued certificate.  When this is used you must run VCert again in pickup mode to retrieve the certificate that was requested. |
| `--pickup-id-file`   | Use to specify a file name where the unique identifier for the certificate will be stored for subsequent use by pickup, renew, and revoke actions.  Default is to write the Pickup ID to STDOUT. |
| `--san-dns`          | Use to specify a DNS Subject Alternative Name. To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-dns one.example.com` `--san-dns two.example.com` |
| `--valid-days`       | Use to specify the number of days a certificate needs to be valid.<br/>Example: `--valid-days 30` |
| `-z`                 | Use to specify the DevOps Project Zone where the certificate will be located.<br/>Example: `-z vvvvvvvv-wwww-xxxx-yyyy-zzzzzzzzzzzz` |

## Certificate Retrieval Parameters
```
VCert pickup -k <api key> [--pickup-id <request id> | --pickup-id-file <file name>]
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ------------------ | ------------------------------------------------------------ |
| `--cert-file`      | Use to specify the name and location of an output file that will contain only the end-entity certificate.<br/>Example: `--cert-file /path-to/example.crt` |
| `--chain`          | Use to include the certificate chain in the output, and to specify where to place it in the file.<br/>Options:  `root-last` (default), `root-first`, `ignore` |
| `--chain-file`     | Use to specify the name and location of an output file that will contain only the root and intermediate certificates applicable to the end-entity certificate. |
| `--file`           | Use to specify a name and location of an output file that will contain certificates when they are not written to their own files using `--cert-file` and/or `--chain-file`.<br/>Example: `--file /path-to/keycert.pem` |
| `--format`         | Use to specify the output format.<br/>Options: `pem` (default), `json` |
| `--pickup-id`      | Use to specify the unique identifier of the certificate returned by the enroll or renew actions if `--no-pickup` was used or a timeout occurred. Required when `--pickup-id-file` is not specified. |
| `--pickup-id-file` | Use to specify a file name that contains the unique identifier of the certificate returned by the enroll or renew actions if --no-pickup was used or a timeout occurred. Required when `--pickup-id` is not specified. |


## Certificate Renewal Parameters
```
VCert renew -k <api key> [--id <request id> | --thumbprint <sha1 thumb>]
```
Options:

| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Command&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description                                                  |
| ------------------ | ------------------------------------------------------------ |
| `--cert-file`      | Use to specify the name and location of an output file that will contain only the end-entity certificate.<br/>Example: `--cert-file /path-to/example.crt` |
| `--chain`          | Use to include the certificate chain in the output, and to specify where to place it in the file.<br/>Options: `root-last` (default), `root-first`, `ignore` |
| `--chain-file`     | Use to specify the name and location of an output file that will contain only the root and intermediate certificates applicable to the end-entity certificate. |
| `--cn`             | Use to specify the common name (CN). This is required for Enrollment. |
| `--csr`            | Use to specify the CSR and private key location. Options: `local` (default), `file`<br />- local: private key and CSR will be generated locally<br />- file: CSR will be read from a file by name<br />Example: `--csr file:/path-to/example.req` |
| `--file`           | Use to specify a name and location of an output file that will contain the private key and certificates when they are not written to their own files using `--key-file`, `--cert-file`, and/or `--chain-file`.<br/>Example: `--file /path-to/keycert.pem` |
| `--format`         | Use to specify the output format.  The `--file` option must be used with the PKCS#12 format to specify the keystore file.<br/>Options: `pem` (default), `json`, `pkcs12` |
| `--id`             | Use to specify the unique identifier of the certificate returned by the enroll or renew actions.  Value may be specified as a string or read from a file by using the file: prefix.<br/>Example: `--id file:cert_id.txt` |
| `--key-file`       | Use to specify the name and location of an output file that will contain only the private key.<br/>Example: `--key-file /path-to/example.key` |
| `--key-password`   | Use to specify a password for encrypting the private key. For a non-encrypted private key, specify `--no-prompt` without specifying this option. You can specify the password using one of three methods: at the command line, when prompted, or by using a password file. |
| `--key-size`       | Use to specify a key size for RSA keys. Default is 2048.     |
| `--no-pickup`      | Use to disable the feature of VCert that repeatedly tries to retrieve the issued certificate.  When this is used you must run VCert again in pickup mode to retrieve the certificate that was requested. |
| `--omit-sans`      | Ignore SANs in the previous certificate when preparing the renewal request. Workaround for CAs that forbid any SANs even when the SANs match those the CA automatically adds to the issued certificate. |
| `--pickup-id-file` | Use to specify a file name where the unique identifier for the certificate will be stored for subsequent use by `pickup`, `renew`, and `revoke` actions.  By default it is written to STDOUT. |
| `--san-dns`          | Use to specify a DNS Subject Alternative Name. To specify more than one, simply repeat this parameter for each value.<br/>Example: `--san-dns one.example.com` `--san-dns two.example.com` |
| `--thumbprint`     | Use to specify the SHA1 thumbprint of the certificate to renew. Value may be specified as a string or read from the certificate file using the `file:` prefix. |


## Examples

For the purposes of the following examples assume that the Venafi Cloud REST API is accessible at https://api.venafi.cloud, that a user has been registered and granted at least the "DevOps" role, and that the user has an API key of "3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4". Also assume that a CA Account and Issuing Template has been created and configured appropriately (organization, city, state, country, key length, allowed domains, etc.). Lastly, that a DevOps project has been created to which the user has been given access, and a zone has been created within the project that has an ID of "126e4141-c299-4b45-bf4d-ae28cd3e061b".

Use the help to view the command line syntax for enroll:
```
VCert enroll -h
```
Submit a Venafi Cloud request for enrolling a certificate with a common name of “first-time.venafi.example” using an authentication token and have VCert prompt for the password to encrypt the private key:
```
VCert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z 126e4141-c299-4b45-bf4d-ae28cd3e061b --cn first-time.venafi.example
```
Submit a Venafi Cloud request for enrolling a certificate where the password for encrypting the private key to be generated is specified in a text file called passwd.txt:
```
VCert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z 126e4141-c299-4b45-bf4d-ae28cd3e061b --key-password file:passwd.txt --cn passwd-from-file.venafi.example
```
Submit a Venafi Cloud request for enrolling a certificate where the private key to be generated is not password encrypted:
```
VCert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z 126e4141-c299-4b45-bf4d-ae28cd3e061b --cn non-encrypted-key.venafi.example --no-prompt
```
Submit a Venafi Cloud request for enrolling a certificate using an externally generated CSR:
```
VCert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z 126e4141-c299-4b45-bf4d-ae28cd3e061b --csr file:/opt/pki/cert.req
```
Submit a Venafi Cloud request for enrolling a certificate where the certificate and private key are output using JSON syntax to a file called json.txt:
```
VCert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z 126e4141-c299-4b45-bf4d-ae28cd3e061b --key-password Passw0rd --cn json-to-file.venafi.example --format json --file keycert.json
```
Submit a Venafi Cloud request for enrolling a certificate where only the certificate and private key are output, no chain certificates:
```
VCert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z 126e4141-c299-4b45-bf4d-ae28cd3e061b --key-password Passw0rd --cn no-chain.venafi.example --chain ignore
```
Submit a Venafi Cloud request for enrolling a certificate with three DNS subject alternative names:
```
VCert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z 126e4141-c299-4b45-bf4d-ae28cd3e061b --no-prompt --cn three-sans.venafi.example --san-dns first-san.venafi.example --san-dns second-san.venafi.example --san-dns third-san.venafi.example
```
Submit a Venafi Cloud request for enrolling a certificate where the certificate is not issued after two minutes and then subsequently retrieve that certificate after it has been issued:
```
VCert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z 126e4141-c299-4b45-bf4d-ae28cd3e061b --no-prompt --cn demo-pickup.venafi.example

VCert pickup -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 --pickup-id "{7428fac3-d0e8-4679-9f48-d9e867a326ca}"
```
Submit a Venafi Cloud request for enrolling a certificate that will be retrieved later using a Pickup ID from in a text file:
```
VCert enroll -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 -z 126e4141-c299-4b45-bf4d-ae28cd3e061b --no-prompt --cn demo-pickup.venafi.example --no-pickup -pickup-id-file pickup_id.txt

VCert pickup -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 --pickup-id-file pickup_id.txt
```
Submit a Venafi Cloud request for renewing a certificate using the enrollment (pickup) ID of the expiring certificate:
```
VCert renew -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 --id "{7428fac3-d0e8-4679-9f48-d9e867a326ca}"
```
Submit a Venafi Cloud request for renewing a certificate using the expiring certificate file:
```
VCert renew -k 3dfcc6dc-7309-4dcf-aa7c-5d7a2ee368b4 --thumbprint file:/opt/pki/demo.crt
```

## Appendix

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
