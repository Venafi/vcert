# VCert Playbook 

VCert Playbook functionality solves the last mile problem for clients. Vcert does a great job fetching the certificate, 
but clients often have to write scripts around it to install it in the right location and take action after the 
certificate is downloaded. The Playbook functionality aims to support this use case natively. It makes pull provisioning 
very easy for clients.

## Key Features of Playbook.

1. Users don't have to pass long command line arguments. They can now call VCert with playbook yaml files. A huge help 
in automation and maintenance. 
2. Users can specify, where the certificate goes once received from Venafi. It supports folder locations as well as 
CAPI store. 
3. Users can specify, any after installation actions need to be taken. E.g. Restart my apache or restart nginx or any 
other script one would like to run after the certificate is available in the right location. 
4. User can mention renewing before, this helps to run the script on daily basis as part of cronjob or automation, the 
tool will check if certificate exists or the certificate requires renewal before fetching a new certificate based on 
the values configured. 
5. Supports many formats of certificate to be stored, PKCS12, JKS, PEM, and CAPI store.

## Some use cases:
1. A client having 100s of Microsoft servers can have this script as part of the scheduled job.  The tool will run, 
check if the certificate  present in the CAPI store needs renewal, if yes, it will fetch a new certificate, and install 
in CAPI. Tool can run any after install script as well. 
2. Remote machines like ATMs, can use this tool to pull provisioning certificates on startup or regular intervals. Once 
the certificate is received, it can run any post-processing scripts configured in the tool.

## Getting started
VCert Playbook is a new cli command that helps you request and retrieve a certificate from a Venafi platform and 
installs them on any number of locations.
It also takes care of token refreshing when the platform is TPP.

## Usage
Run the following: 
```sh
vcert run -f path/to/my/playbook.yaml
```

### Arguments
The following arguments are available to use:

| Argument      | Short | Type    | Description                                                                                                                                                     |
|---------------|-------|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `debug`       | `-d`  | boolean | Enables more detailed logging from the tool                                                                                                                     |
| `file`        | `-f`  | string  | The playbook file to be run by the tool                                                                                                                         |
| `force-renew` |       | boolean | Request a new certificate regardless of the expiration date on the current certificate                                                                          |

### Samples
Handy samples have been provided in the [examples folder](./examples/playbook):
* [Playbook for CAPI store](./examples/playbook/sample.capi.yaml)
* [Playbook for JKS](./examples/playbook/sample.jks.yaml)
* [Playbook for PEM](./examples/playbook/sample.pem.yaml)
* [Playbook for PKCS12](./examples/playbook/sample.pkcs12.yaml)
* [Playbook for multiple installations](./examples/playbook/sample.multi.yaml)
* [Playbook for TLSPC](./examples/playbook/sample.tlspc.yaml)

## Playbook file
The playbook file defines the details of the certificate to request as well as the locations where the certificate will 
be installed. The structure of the file is described in the following table:
### Playbook

| Field        | Type                       | Description |
|--------------|----------------------------|-------------|
| certificates | array of `CertificateTask` |             |
| config       | `Config`                   |             |

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
