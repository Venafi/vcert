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
| certificateTasks | array of [CertificateTask](#certificatetask) | One or more [CertificateTask](#certificatetask) objects. |
| config       | [Config](#config) | A single [Config](#config) object that represents connectivity to either TLS Protect Cloud or TLS Protect Datacenter (TPP) |

### Config

| Field       | Type          | Description                                                                                       |
|-------------|---------------|---------------------------------------------------------------------------------------------------|
| credentials | `Credentials` ||
| trustBundle | string        ||
| type        | string        | Either "tpp" or "tlspdc" for TPP/Datacenter - OR - "vaas" or "tlspc" for TLS Protect Cloud / VaaS |
| url         | string        ||

### Credentials

| Field        | Type                   | Description                                                                                                                                                                                                             |
|--------------|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| accessToken  | `Credentials`          ||
| apikey       | string                 ||
| clientId     | string                 ||
| pkcs12       | `CertificateTask.Name` | Use a configured certificateTask (by name) to reference a certificate to be used for certificate authentication. Only supported by TPP endpoints. Referenced certificateTask must have an installation of type `pkcs12` |
| refreshToken | string                 ||
| scope        | string                 ||


### CertificateTask

| Field         | Type                    | Description                                                                                                                                                                                                                                                                                                                              |
|---------------|-------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| installations | array of `Installation` ||
| name          | string                  ||
| renewBefore   | string                  | Configure auto-renewal threshold for certificates. Either by days, hours, or % remaining of certificate lifetime. For example, 30d renews certificate 30 days before expiration, 10h - 10 hours before expiration, or 15% will renew when 15% of the lifetime is remaining. Use "0" or "disabled" to disable auto-renew. Default is 10%. |
| request       | `Request`               ||
| setenvvars    | array of strings        ||Set to "thumbprint" and/or "serial" to set environment variables. Environment variables will be named VCERT_TASKNAME_THUMBPRINT or VCERT_TASKNAME_SERIAL accordingly, where TASKNAME is the uppercased name provied on the certificate task.

### Installation

| Field                | Type    | Description                                                                                                                                                                                                    |
|----------------------|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| afterInstallAction   | string  | Execute this command after this installation is performed (both enrollment and renewal). On *nix, this uses `/bin/sh -c '<afterInstallAction>'`. On Windows, this uses `powershell.exe '<afterInstallAction>'` |
| capiIsNonExportable  | boolean | Ignored if type is NOT `CAPI`                                                                                                                                                                                  |
| jksAlias             | string  | Required when type is `JKS`                                                                                                                                                                                    |
| jksPassword          | string  | Required when type is `JKS`                                                                                                                                                                                    |
| location             | string  | file location for certificate. (NOTE: When type is `PEM`, this must be a folder location!)                                                                                                                     |
| pemCertFilename      | string  | Required when type is `PEM`                                                                                                                                                                                    |
| pemChainFilename     | string  | Required when type is `PEM`                                                                                                                                                                                    |
| pemKeyFilename       | string  | Required when type is `PEM`                                                                                                                                                                                    |
| type                 | string  | Valid types are `PKCS12`, `PEM`, `JKS`, and `CAPI`                                                                                                                                                             |

### Request

| Field           | Type                   | Description |
|-----------------|------------------------|-------------|
| cadn            | string                 ||
| chainOption     | string                 ||
| csrOrigin       | string                 ||
| customFields    | array of `CustomField` ||
| dnsNames        | array of string        ||
| emails          | array of string        ||
| fetchPrivateKey | boolean                ||
| friendlyName    | string                 ||
| ips             | array of string        ||
| issuerHint      | string                 ||
| keyCurve        | string                 ||
| keyLength       | integer                ||
| keyPassword     | string                 ||
| keyType         | string                 ||
| location        | `Location`             ||
| omitSans        | boolean                ||
| origin          | string                 ||
| subject         | `Subject`              ||
| upns            | array of string        ||
| uris            | array of string        ||
| validDays       | string                 ||
| zone            | string                 ||

### CustomField

| Field   | Type      | Description |
|---------|-----------|-------------|
| type    | string    ||
| name    | string    ||
| value   | string    ||

### Location

| Field      | Type    | Description |
|------------|---------|-------------|
| instance   | string  ||
| tlsAddress | string  ||
| replace    | boolean ||

### Subject

| Field        | Type            | Description |
|--------------|-----------------|-------------|
| commonName   | string          ||
| country      | string          ||
| locality     | string          ||
| organization | string          ||
| orgUnits     | array of string ||
| province     | string          ||
