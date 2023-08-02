# VCert Playbook 

VCert Playbook functionality solves the last mile problem for clients. Vcert does a great job fetching the certificate, 
but clients often have to write scripts around it to install it in the right location and take action after the 
certificate is downloaded. The Playbook functionality aims to support this use case natively. It makes pull provisioning 
very easy for clients.

## Key Features of Playbook.

1. Users don't have to pass long command line arguments. They can now call VCert with playbook yaml files. A huge help 
in automation and maintenance. 
2. Users can specify where the certificate goes and in which format once received from Venafi. It supports common keystore 
formats (PEM, JKS, PKCS#12) in folder locations as well as Windows CAPI store. 
3. Users can specify any after installation actions need to be taken. E.g. Restart services (apache, nginx) or any 
other script one would like to run after the certificate is available in the right location. 
4. Renewal parameters can be setup to automatically renew the certificate before it expires. This model assumes that vcert 
is added to a daily cronjob or is executed on a regular basis by some other automation. Default renewal is 10% of remaining 
certificate lifetime.
5. VCert will also automatically update API access tokens / refresh tokens within the playbook when using TLS Protect Datacenter 
/ Trust Protection Platform. This functionality enables ongoing operation without intervention correctly utilizing a
refresh token to get a new access token when necessary. This approach works well when the refresh/grant token lifetime is
sufficiently long, in coordination with a short-lived access token. (i.e. 3 years/1 hour)
6. VCert Playbook functionality works with both TLS Protect Cloud (VaaS) and TLS Protect Datacenter (TPP)

## Getting started
VCert Playbook functionality is invoked using the `vcert run` cli command. that helps you request and retrieve a certificate from a Venafi platform and 
installs them on any number of locations.

1. Create a YAML playbook file. 
    - This readme contains all of the valid options and formatting for the YAML playbook. 
    - Sample YAML playbook files are also available in the [examples folder](./examples/playbook)
2. Execute the playbook using the `vcert run` command:
    ```sh
    vcert run -f path/to/my/playbook.yaml
    ```
3. Setup a cronjob (or Windows scheduled task) to execute the playbook on a regular basis (usually daily)
    Sample cronjob entry:
    ```
    0 23 * * *     /usr/bin/sudo /usr/local/bin/vcert run -f ~/playbook.yaml >> /var/log/vcert-playbook.log 2>&1
    ```

> **Recommended**: For a detailed walkthrough for automating certificate lifecycle management using a VCert Playbook for NGINX, check out the guide on [Dev Central](https://developer.venafi.com/tlsprotectcloud/docs/vcert-auto-cert-mgt-using-tlspc)!

## Usage
VCert run playbook functionality is invoked using the `run` command with optional additional arguments:
```sh
vcert run [OPTIONAL ARGUMENTS]
```

For example, the following command will execute the playbook in ./path/to/my/playbook.yaml with debug output enabled:
```sh
vcert run --file path/to/my/playbook.yaml --debug
```


### Arguments
The following arguments are available to use:

| Argument      | Short | Type    | Description                                                                                                                                                     |
|---------------|-------|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--debug`       | `-d`  | boolean | Enables more detailed logging from the tool                                                                                                                     |
| `--file`        | `-f`  | string  | The playbook file to be run by the tool (defaults to playbook.yaml in current directory)                                                                                                                         |
| `--force-renew` |       | boolean | Request a new certificate regardless of the expiration date on the current certificate                                                                          |

### Playbook Samples
Handy samples have been provided in the [examples folder](./examples/playbook):
* [Playbook for CAPI store](./examples/playbook/sample.capi.yaml)
* [Playbook for JKS](./examples/playbook/sample.jks.yaml)
* [Playbook for PEM](./examples/playbook/sample.pem.yaml)
* [Playbook for PKCS12](./examples/playbook/sample.pkcs12.yaml)
* [Playbook for multiple installations](./examples/playbook/sample.multi.yaml)
* [Playbook for TLSPC](./examples/playbook/sample.tlspc.yaml)

# Playbook file structure and options
The playbook file is a YAML file that defines the following structure and types. Each playbook defines the details of one or more certificates to be requested as well as the locations where the certificate will be installed. 

The top-level structure of the playbook file is described as:


| Field        | Type                       | Description |
|--------------|----------------------------|-------------|
| certificateTasks | array of [CertificateTask](#certificatetask) | ***REQUIRED*** - One or more [CertificateTask](#certificatetask) objects. |
| config       | ***REQUIRED*** - [Config](#config) | A single [Config](#config) object that represents connectivity to either TLS Protect Cloud or TLS Protect Datacenter (TPP) |

### Config

| Field       | Type          | Description                                                                                       |
|-------------|---------------|---------------------------------------------------------------------------------------------------|
| connection | [Connection](#connection) | ***REQUIRED*** - A [Connection](#connection) object that specifies the provider (TLPSC or TLSPDC) and associated configuration to fulfill certificate requests |

### Connection
| Field        | Type                              | Description |
|--------------|-----------------------------------|-------------|
| credentials  | [Credential](#credentials)        | ***REQUIRED*** - An [Credential](#credential) object that defines the credentials used to connect to the selected provider platform |
| insecure     | `bool`                            | *OPTIONAL* - Default `false`. When set to `true`, ignore certificate errors when connecting. |
| platform     | `string`                          | ***REQUIRED*** - Either `tpp` or `vaas`. Designates which Venafi platform to connect to. `tlspc` is a valid alias for `tpp`. `tlspc` is a valid alias for `vaas`. |
| trustBundle  | `string`                          | *OPTIONAL* - Defines path to PEM formated trust bundle that contains the root (and optionally intermediate certificates) to use to trust the TLS connection. If omitted, will attempt to use operating system trusted CAs. |
| url          | `string`                          | ***REQUIRED*** when platform is `tpp`. *OPTIONAL* when platform is `vaas` (defaults to api.venafi.cloud). If url string does not include `https://` it will be added automatically. For connection to TPP, url must include the full API path (i.e. `https://tpp.company.com/vedsdk/`)

### Credential

| Field        | Type                              | Description |
|--------------|-----------------------------------|-------------|
| apikey       | string                            | ***REQUIRED*** - when [Connection.platform](#connection) is `vaas`. *IGNORED* otherwise. |
| accessToken  | string                            | *OPTIONAL* - Used when [Connection.platform](#connection) is `tpp` for authenticating to the REST API. If omitted, or invalid, expired, vcert will attempt to use the [Credential.p12Task](#credential) or [Credential.refreshToken](#credential) to get a valid accessToken. Upon successful refresh, this value will be overwritten with the new valid accessToken. *IGNORED* when [Connection.platform](#connection) is `vaas` or `tlspc` |
| clientId     | string                            | *OPTIONAL* - Used when [Connection.platform](#connection) is `tpp` to map to the API integration to be used. If omitted, uses `vcert-cli` as default. *IGNORED* when [Connection.platform](#connection) is `vaas` or `tlspc`|
| p12Task       | string | *OPTIONAL* - Used when [Connection.platform](#connection) is `tpp` to reference a configured [CertificateTask.name](#certificatetask) to be used for certificate authentication. Will be used to get a new accessToken when `accessToken` is missing, invalid, or expired. Referenced certificateTask must have an installation of type `pkcs12`. |
| refreshToken | string                            | *OPTIONAL* - Used when [Connection.platform](#connection) is `tpp` to refresh the `accessToken` if it is missing, invalid, or expired. If omitted, the `accessToken` will not be refreshed when it expires. When a refresh token is used, a new accessToken *and* refreshToken are issued. The previous refreshToken is then invalid (one-time use only). vCert will attempt to update the refreshToken and accessToken fields upon refresh. |
| scope        | string                            | *OPTIONAL* - Used when [Connection.platform](#connection) is `tpp` to determine the scope of the access token when refreshing the access token, or when getting a new grant using a `pkcs12` certificate. Defaults to `certificate:manage` if omitted.|


### CertificateTask

| Field         | Type                              | Description |
|---------------|-----------------------------------|-------------|
| name          | string                            | ***REQUIRED*** - The name of the certificate task within the playbook. Used in output messages to distinguish tasks when multiple certificate tasks are defined, also, referred to by [Credential.p12Task](#credential) when specifying a certificate to use to refresh [Credential.accessToken](#credential). If more than one [CertificateTask](#certificatetask) exists, each name must be unique. |
| installations | array of [Installation](#installation) objects | ***REQUIRED*** - Specifies one or more locations in which format and where the certificate requested will be stored. |
| renewBefore   | string                            | *OPTIONAL* - Configure auto-renewal threshold for certificates. Either by days, hours, or % remaining of certificate lifetime. For example, 30d renews certificate 30 days before expiration, 10h - 10 hours before expiration, or 15% will renew when 15% of the lifetime is remaining. Use "0" or "disabled" to disable auto-renew. Default is 10%. |
| request       | [Request](#request)               | ***REQUIRED*** - The [Request](#request) object specifies the details about the certificate to be requested such as commonname, SANs, etc. |
| setEnvVars    | array of strings                  | *OPTIONAL* - Specify details about the certificate to be set as environment variables before the [Installation.afterInstallAction](#installation) is executed. Supported options are `thumbprint`, `serial`, and `base64` (which sets the entire base64 of the certificate retrieved as an environment variable). Environment variables will be named VCERT_TASKNAME_THUMBPRINT, VCERT_TASKNAME_SERIAL, or VCERT_TASKNAME_BASE64 accordingly, where TASKNAME is the uppercased [CertificateTask.name](#certificatetask). |

### Installation

| Field                | Type    | Description |
|----------------------|---------|-------------|
| format               | string  |  ***REQUIRED*** - Specifies the format type for the installed certificate. Valid types are `PKCS12`, `PEM`, `JKS`, and `CAPI` |
| afterInstallAction   | string  | *OPTIONAL* - Execute this command after this installation is performed (both enrollment and renewal). On *nix, this uses `/bin/sh -c '<afterInstallAction>'`. On Windows, this uses `powershell.exe '<afterInstallAction>'` |
| backupFiles          | boolean | *OPTIONAL* - When `true`, backup existing certificate files before replacing during a renewal operation. Defaults to `false` |
| file                 | string  | ***REQUIRED*** when [Installation.format](#installation) is `PKCS#12`, `PEM`, or `JKS`. Specifies the file path and name for the certificate file (PEM) or PKCS#12 / JKS bundle. Example `/etc/ssl/certs/myPEMfile.cer`, `/etc/ssl/certs/myPKCS12.p12`, or `/etc/ssl/certs/myJKS.jks`. *IGNORED* for other values of [Installation.format](#installation) |
| jksAlias             | string  | ***REQUIRED*** when [Installation.format](#installation) is `JKS`. Specifies the certificate alias value within the Java Keystore. *IGNORED* when [Installation.format](#installation) is not `JKS` |
| jksPassword          | string  | ***REQUIRED*** when [Installation.format](#installation) is `JKS`. Specifies the password for the JKS. *IGNORED* when [Installation.format](#installation) is not `JKS`. |
| chainFile            | string  | ***REQUIRED*** when [Installation.format](#installation) is `PEM`. Specifies the file path and name for the chain PEM bundle (Example `/etc/ssl/certs/myChain.cer`). *IGNORED* for other values of [Installation.format](#installation) |
| keyFile              | string  | ***REQUIRED*** when [Installation.format](#installation) is `PEM`. Specifies the file path and name for the private key PEM file (Example `/etc/ssl/certs/myKey.key`). *IGNORED* for other values of [Installation.format](#installation) |
| location             | string |  ***REQUIRED*** when [Installation.format](#installation) is `CAPI`. Specifies the Windows CAPI store to place the installed certificate. Typically `"LocalMachine\My"` or `"CurrentUser\My"`. *IGNORED* if [Installation.format](#installation) is NOT `CAPI`. **NOTE:** if the location is not contained within `"`, the backslash `\` must be properly escaped (i.e. `LocalMachine\\My`) |
| capiIsNonExportable  | boolean | *OPTIONAL* - When `true`, private key will be flagged as 'Non-Exportable' when stored in Windows CAPI store. *IGNORED* if [Installation.format](#installation) is NOT `CAPI`. Defaults to `false` |

### Request

| Field           | Type                   | Description |
|-----------------|------------------------|-------------|
| cadn            | string                 | *OPTIONAL* - Specify the DN location for a specific CA template to fulfil the request (i.e. "\VED\Policy\CA Templates\Internal CA"). Only valid when [Connection.platform](#connection) is `tpp` |
| chain           | string                 | *OPTIONAL* - Determines the ordering of certificates within the returned chain. Valid options are `root-first`, `root-last`, or `ignore`. Defaults to `root-last`. |
| csr             | string                 | *OPTIONAL* - Specifies where the CSR and PrivateKey are generated: use `local` to generate the CSR and PrivateKey locally, or `service` to have the PrivateKey and CSR generated by the specified [Connection.platform](#connection). Defaults to `local`. |
| fields          | array of [CustomField](#customfield) | *OPTIONAL* - Each [CustomField](#customfield) sets the specified custom field on certificate object. Only valid when [Connection.platform](#connection) is `tpp`. |
| sanDNS          | array of string        | *OPTIONAL* - Specify one or more DNS SAN entries for the requested certificate |
| sanEmail        | array of string        | *OPTIONAL* - Specify one or more Email SAN entries for the requested certificate |
| nickname        | string                 | *OPTIONAL* - Specify the certificate object name to be created in TPP for the requested certificate. If not specified, TPP will use the [Subject.commonName](#subject). Only valid when [Connection.platform](#connection) is `tpp`|
| sanIP           | array of string        | *OPTIONAL* - Specify one or more IP SAN entries for the requested certificate |
| issuerHint      | string                 | *OPTIONAL* - Used only when [Request.validDays](#request) is specified to determine the correct Specific End Date attribute to set on the TPP certificate object. Valid options are `DIGICERT`, `MICROSOFT`, `ENTRUST`, `ALL_ISSUERS`. If not defined, but validDays are set, the attribute 'Specific End Date' will be used. Only valid when [Connection.platform](#connection) is `tpp` |
| keyCurve        | string                 | ***REQUIRED*** when [Request.keyType](#request) is `ECDSA`, `EC`, or `ECC`. Valid values are `P256`, `P384`, `P521`, `ED25519`. |
| keySize         | integer                | *OPTIONAL* - Specifies the key size when specified [Request.keyType](#request) is `RSA`. Defaults to 2048. |
| keyPassword     | string                 | ***REQURED*** when [Installation.format](#installation) is `JKS` or `PKCS#12`. Otherwise **OPTIONAL**. Specifies the password to encrypt the private key. If not specified for `PEM` [Installation.format](#installation), the private key will be stored in an unencrypted PEM format. |
| keyType         | string                 | *OPTIONAL* - Specify the key type of the requested certificate. Valid options are `RSA`, `ECDSA`, `EC`, `ECC` and `ED25519`. Default is `RSA` |
| location        | [Location](#location)  | *OPTIONAL* - Use to provide the name/address of the compute instance and an identifier for the workload using the certificate. This results in a device (node) and application (workload) being associated with the certificate in the Venafi Platform.<br/>Example: `node:workload` |
| appInfo         | string                 | *OPTIONAL* - Sets the origin attribute on the certificate object in TPP. Only valid when [Connection.platform](#connection) is `tpp`. |
| subject         | [Subject](#subject)    | ***REQUIRED*** - defines the [Subject](#subject) information for the requested certificate |
| sanUPN          | array of string        | *OPTIONAL* - Specify one or more UPN SAN entries for the requested certificate |
| sanURI          | array of string        | *OPTIONAL* - Specify one or more URI SAN entries for the requested certificate |
| validDays       | string                 | *OPTIONAL* - Specify the number of days the certificate should be valid for. Only supported by specific CAs, and only if [Connection.platform](#connection) is `tpp`. The number of days can be combined with an "issuer hint" to correctly set the right parameter for the desired CA. For example, `"30#m"` will specify a 30-day certificate from a Microsoft issuer. Valid hints are `m` for Microsoft, `d` for Digicert, `e` for Entrust. If an issuer hint is not specified, the generic attribute 'Specific End Date' will be used. |
| zone            | string                 | ***REQUIRED*** - Specifies the Policy Folder (for TPP) or the Application and Issuing Template to use (for VaaS). For TPP, exclude the "\VED\Policy" portion of the folder path. **NOTE:** if the zone is not contained within `"`, the backslash `\` must be properly escaped (i.e. `Certificates\\vCert`) |

### Subject

| Field        | Type            | Description |
|--------------|-----------------|-------------|
| commonName   | string          | ***REQUIRED*** - Specifies the CN= (CommonName) attribute of the requested certificate. |
| country      | string          | *OPTIONAL* - Specifies the C= (Country) attribute of the requested certificate. |
| locality     | string          | *OPTIONAL* - Specifies the L= (City) attribute of the requested certificate. |
| organization | string          | *OPTIONAL* - Specifies the O= (Organization) attribute of the requested certificate. |
| orgUnits     | array of string | *OPTIONAL* - Specifies one or more OU= (Organization Unit) attribute of the requested certificate. |
| province     | string          | *OPTIONAL* - Specifies the S= (State) attribute of the requested certificate. |

### CustomField

| Field   | Type      | Description |
|---------|-----------|-------------|
| name    | string    | ***REQUIRED*** - Adds a custom-field entry with name to the certificate object. The custom field must already be defined in TPP. |
| value   | string    | ***REQUIRED*** - Specifies the custom-field value to the certificate object. |

### Location

| Field      | Type    | Description |
|------------|---------|-------------|
| instance   | string  | ***REQUIRED*** - Specifies the name of the installed node (typically the hostname). |
| tlsAddress | string  | ***REQUIRED*** - Specifies the IP address or hostname and port where the certificate can be validated by the Venafi Platform. <br/>Example: `192.168.100.23:443`. |
| replace    | boolean | *OPTIONAL* - Replace the current object with new information. Defaults to `false`.|


