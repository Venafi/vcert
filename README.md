# VCert

<img src="https://www.venafi.com/sites/default/files/content/body/Light_background_logo.png" width="330px" height="69px"/>  

VCert is a Go library, SDK, and command line utility designed to simplify key generation and enrollment of machine identities
(also known as SSL/TLS certificates and keys) that comply with enterprise security policy by using the
[Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or [Venafi Cloud](https://pki.venafi.com/venafi-cloud/).

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

## Usage example

For code samples of programmatic use, please review the files in [/example](/example).

1. In your main.go file, make the following import declarations:  `github.com/Venafi/vcert`, `github.com/Venafi/vcert/pkg/certificate`, and `github.com/Venafi/vcert/pkg/endpoint`.
2. Create a configuration object of type `&vcert.Config` that specifies the Venafi connection details.  Solutions are typically designed to get those details from a secrets vault, .ini file, environment variables, or command line parameters.
3. Instantiate a client by calling the `NewClient` method of the vcert class with the configuration object.
4. Compose a certiticate request object of type `&certificate.Request`.
5. Generate a key pair and CSR for the certificate request by calling the `GenerateRequest` method of the client.
6. Submit the request by passing the certificate request object to the `RequestCertificate` method of the client.
7. Use the request ID to pickup the certificate using the `RetrieveCertificate` method of the client.

Samples are in a state where you can build/execute them using the following commands (after setting the environment variables discussed later): 

```sh
go build -o cli ./example
go test -v ./example -run TestRequestCertificate
```

For command line examples, please see the [Knowledge Base at support.venafi.com](https://support.venafi.com/hc/en-us/articles/217991528-Introducing-VCert-API-Abstraction-for-DevOpsSec).

## Testing with Trust Protection Platform and Cloud

Unit tests:

```sh
make test
```

Integration tests for Trust Protection Platform and Cloud products require endpoint connection variables:

```sh
export VCERT_TPP_URL=https://tpp.venafi.example/vedsdk
export VCERT_TPP_USER=tpp-user
export VCERT_TPP_PASSWORD=tpp-password
export VCERT_TPP_ZONE='some\policy'

make tpp_test
```

```sh
export VCERT_CLOUD_URL=https://api.venafi.cloud/v1
export VCERT_CLOUD_APIKEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export VCERT_CLOUD_ZONE=Default

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

1. Fork it (<https://github.com/yourname/yourproject/fork>)
2. Create your feature branch (`git checkout -b Venafi/vcert`)
3. Commit your changes (`git commit -am 'Added some cool functionality'`)
4. Push to the branch (`git push origin Venafi/vcert`)
5. Create a new Pull Request

## Release History

- 3.18.3.1
  - First open source release

## License

Copyright &copy; Venafi, Inc. All rights reserved.

VCert is licensed under the Apache License, Version 2.0. See `LICENSE` for the full license text.

Please direct questions/comments to opensource@venafi.com.