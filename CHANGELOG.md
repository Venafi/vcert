## 5.10.2 (June 18th, 2025)
- Allow to set a GCM Certificate scope without a certificate name.

## 5.10.1 (June 12th, 2025)
- Add support to provide GCM Certificate Scope for Provision Cloudkeystore

## 5.10.0 (May 30th, 2025)
- Support for Linux ARM 32 bit Binaries

## 5.9.1 (May 28th, 2025)
- Add missing support to use --platform flag with the following commands:
  - pickup 
  - renew 
  - retire 
  - getpolicy 
  - setpolicy

## 5.9.0 (April 19th, 2025)
- TPP v25.1 support

## 5.8.3 (March 19th, 2025)
- Fix for Playbook's backup functionality ([#549](https://github.com/Venafi/vcert/issues/549))

## 5.8.2 (March 7th, 2025)
- Fix: fixes VCert logger import

## 5.8.1 (January 17th, 2025)
- Fix: bumps libraries

## 5.8.0 (January 6th, 2025)
- Enables RSA 3072 bit key size for TPP (VCert SDK)

## 5.7.1 (June 7th, 2024)
- Support for VCP Provisioning (final release)

## 5.7.0: (May 28th, 2024)
- Support for VCP Provisioning - (Pre-release)

## 5.7.0-rc2 (May 22nd, 2024)
- Enables Certificate Provisioning with Service Account Auth
- Adds ability to provision certificate using keystore and provider name

## 5.7.0-rc1 (May 8th, 2024)
- NEW FEATURE: Support for VCP Provisioning (api-key support only)

## 5.6.4 (April 11th, 2024)
- Fix issues with proxy.golang.org which were introduced in VCert 5.6.3.

## 5.6.3 (April 9th, 2024)

General:
- Updates all playbook samples, removing deprecated attributes and making sure they work out-of-the-box

VCert SDK:
- Adds `TokenURL` to `endpoint.Authentication`
- Cloud Connector will stop using the `TokenURL` attribute from `endpoint.OAuthProvider` and start using the new one 
(above)

VCert CLI:
- Internal changes to make use fo the new `TokenURL` attribute
- Renames `getcred` command flag `--idp-jwt` back to `--external-jwt`
- Fixes an issue whereby using `getcred` command to request a `TPP` access token by using username/password threw the 
deprecation warning message. This should not happen for `getcred` command
- Fixes an issue whereby requesting an access token for `VCP` platform printed the wrong expiration date. Now it 
properly prints the expiration date 

VCert SDK:
- Adds new attribute `config.connection.credentials.tokenURL` to playbook file. This attribute should be used to pass 
the `VCP` token url value
- Stops using `config.connection.credentials.idP.tokenURL` for the `VCP` token url value
- Enhances the task run. Now, a failed task will not terminate the playbook execution, instead it will run all tasks and 
errors will be reported at the end of the run.

## 5.6.2 (April 4th, 2024)
VCert SDK:
- Removes `TenantID` from `endpoint.Authentication` struct
- `cloud.Connector` will use `endpoint.Authentication.OAuthProvider.TokenURL` instead of building the URL (using the 
`tenantID`) to obtain the access token

VCert CLI:
- Removes `--tenant-id` flag for `getcred` command
- Adds `--token-url` flag for `getcred` command

VCert Playbook:
- Removes `tenantId` attribute from `config.connection.credentials` object
- Now uses `config.connection.credentials.idP.tokenURL` for Venafi Control Plane service account authentication

## 5.6.1 (April 2nd, 2024)
VCert SDK:
- Adds UserAgent header to api requests for TPP, Cloud and Firefly connectors
- Adds functionality to convert a Platform type to a ConnectorType enum

## 5.6.0 (March 28th, 2024)
VCert SDK:
- Adds support for service account authentication in Cloud connector

VCert CLI:
- Adds new attributes to `getcred` command: `tenant-id` and `external-jwt` for Venafi Control Plane (VCP) service 
account authentication

VCert playbook:
- Adds support for service account authentication to VCert playbooks