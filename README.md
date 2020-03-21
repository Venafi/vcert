![Venafi](Venafi_logo.png)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & Cloud](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20Cloud-f9a90c)  
_This open source project is community-supported. To report a problem or share an idea, use the
**[Issues](../../issues)** tab; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use the **[Pull requests](../../pulls)** tab to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions._

# VCert

[![GoDoc](https://godoc.org/github.com/Venafi/vcert?status.svg)](https://godoc.org/github.com/Venafi/vcert)  [![Go Report Card](https://goreportcard.com/badge/github.com/Venafi/vcert)](https://goreportcard.com/report/github.com/Venafi/vcert)
[![Used By](https://sourcegraph.com/github.com/Venafi/vcert/-/badge.svg)](https://sourcegraph.com/github.com/Venafi/vcert?badge)

VCert is a Go library, SDK, and command line utility designed to simplify key generation and enrollment of machine identities
(also known as SSL/TLS certificates and keys) that comply with enterprise security policy by using the
[Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or [Venafi Cloud](https://pki.venafi.com/venafi-cloud/).

#### Compatibility

VCert releases are tested using the latest version of Trust Protection Platform.  General functionality of the
[latest VCert release](../../releases/latest) should be compatible with Trust Protection Platform 17.3 or higher.
Custom Fields and Instance Tracking require TPP 18.2 or higher, and Token Authentication requires TPP 19.2 or higher.

## Installation

1. Configure your Go environment according to https://golang.org/doc/install.
2. Verify that GOPATH environment variable is set correctly
3. Download the source code:

```sh
go get github.com/Venafi/vcert
```

or

```sh
git clone https://github.com/Venafi/vcert.git $GOPATH/src/github.com/Venafi/vcert
```
4. Build the command line utilities for Linux, MacOS, and Windows:

```sh
make build
```

## Usage examples

For code samples of programmatic use, please review the files in [/examples](/examples/).

### Common part
1. In your main.go file, make the following import declarations:  `github.com/Venafi/vcert`, `github.com/Venafi/vcert/pkg/certificate`, and `github.com/Venafi/vcert/pkg/endpoint`.
1. Create a configuration object of type `&vcert.Config` that specifies the Venafi connection details.  Solutions are typically designed to get those details from a secrets vault, .ini file, environment variables, or command line parameters.

### Enroll certificate
1. Instantiate a client by calling the `NewClient` method of the vcert class with the configuration object.
1. Compose a certiticate request object of type `&certificate.Request`.
1. Generate a key pair and CSR for the certificate request by calling the `GenerateRequest` method of the client.
1. Submit the request by passing the certificate request object to the `RequestCertificate` method of the client.
1. Use the request ID to pickup the certificate using the `RetrieveCertificate` method of the client.

### New TLS listener for domain
1. Call `vcert.Config` method `NewListener` with list of domains as arguments. For example `("test.example.com:8443", "example.com")`
2. Use gotten `net.Listener` as argument to built-in `http.Serve` or other https servers. 

Samples are in a state where you can build/execute them using the following commands (after setting the environment variables discussed later): 

```sh
go build -o cli ./example
go test -v ./example -run TestRequestCertificate
```

For command line examples, please see the [Knowledge Base at support.venafi.com](https://support.venafi.com/hc/en-us/articles/217991528-Introducing-VCert-API-Abstraction-for-DevOpsSec).

## Prerequisites for using with Trust Protection Platform

1. A user account that has been granted WebSDK Access
2. A folder (zone) where the user has been granted the following permissions: View, Read, Write, Create, Revoke (for the revoke action), and Private Key Read (for the pickup action when CSR is service generated)
3. Policy applied to the folder which specifies:
    1. CA Template that Trust Protection Platform will use to enroll certificate requests submitted by VCert
    2. Subject DN values for Organizational Unit (OU), Organization (O), City (L), State (ST) and Country (C)
    3. Management Type not locked or locked to 'Enrollment'
    4. Certificate Signing Request (CSR) Generation not locked or locked to 'Service Generated CSR'
    5. Generate Key/CSR on Application not locked or locked to 'No'
    6. (Recommended) Disable Automatic Renewal set to 'Yes'
    7. (Recommended) Key Bit Strength set to 2048 or higher
    8. (Recommended) Domain Whitelisting policy appropriately assigned

The requirement for the CA Template to be assigned by policy follows a long standing Venafi best practice which also met our design objective to keep the certificate request process simple for VCert users. If you require the ability to specify the CA Template with the request you can use the TPP REST APIs but please be advised this goes against Venafi recommendations.

## Testing with Trust Protection Platform and Cloud

Unit tests:

```sh
make test
```

Integration tests for Trust Protection Platform and Cloud products require endpoint connection variables (Venafi Cloud products display the API key and Zone values in the user interface):

```sh
export TPP_URL=https://tpp.venafi.example/vedsdk
export TPP_USER=tpp-user
export TPP_PASSWORD=tpp-password
export TPP_ZONE='some\policy'

make tpp_test
```

```sh
export CLOUD_URL=https://api.venafi.cloud/v1
export CLOUD_APIKEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export CLOUD_ZONE=zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz

make cloud_test
```

Command line utility tests make use of [Cucumber & Aruba](https://github.com/cucumber/aruba) feature files.

- To run tests for all features in parallel:

```sh
make cucumber
```

- To run tests only for a specific feature (e.g. basic, config, enroll, format, gencsr, renew, or revoke):

```sh
make cucumber FEATURE=./features/basic/version.feature
```

When run, these tests will be executed in their own Docker container using the Ruby version of Cucumber.  
The completed test run will report on the number of test "scenarios" and "steps" that passed, failed, or were skipped. 

## Contributing to VCert

Venafi welcomes contributions from the developer community.

1. Fork it to your account (https://github.com/Venafi/vcert/fork)
2. Clone your fork (`git clone git@github.com:youracct/vcert.git`)
3. Create a feature branch (`git checkout -b your-branch-name`)
4. Implement and test your changes
5. Commit your changes (`git commit -am 'Added some cool functionality'`)
6. Push to the branch (`git push origin your-branch-name`)
7. Create a new Pull Request (https://github.com/youracct/vcert/pull/new/your-branch-name)

## License

Copyright &copy; Venafi, Inc. All rights reserved.

VCert is licensed under the Apache License, Version 2.0. See `LICENSE` for the full license text.

Please direct questions/comments to opensource@venafi.com.
