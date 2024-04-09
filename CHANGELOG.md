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