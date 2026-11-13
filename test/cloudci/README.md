# cloudci: CI-managed cloud providers and keystores

`cloudci` creates the cloud providers and keystores the vcert CI tests against, checks the cloud provider and
keystore operations on them, and deletes them again at the end of the run, along with any certificates the
tests provisioned to them. The CI starts and ends every run with no cloud providers or keystores of its own
in the tenant.

It runs once per platform: CyberArk Certificate Manager, SaaS (`-target vcp`) and Palo Alto Networks Next-Gen
Trust Security (`-target ngts`).

```sh
go run ./test/cloudci setup    -target vcp -state vcp-state.json -aws-config aws_crud.json -azure-config azure_crud.json
go run ./test/cloudci check    -target vcp -state vcp-state.json -aws-config aws_crud.json -azure-config azure_crud.json
# ... provisioning tests, which read the keystores from vcp-state.json ("env") ...
go run ./test/cloudci teardown -target vcp -state vcp-state.json -aws-config aws_crud.json -azure-config azure_crud.json
```

| Command | What it does |
|---|---|
| `setup` | Creates a cloud provider per configured AWS account and Azure app, validates it (retrying for up to `-validation-timeout`, 10 minutes by default, while cloud IAM changes propagate), then creates the configured keystores. Writes the state file. |
| `check` | Checks the operations on what setup created: configuration read back, renaming, finding by name, discovery settings set, changed one at a time and kept on rename, clearing the schedule, listing machine identities, and that a cloud provider with keystores cannot be deleted. Leaves names as setup created them. |
| `teardown` | Deletes from the cloud the certificates the platform installed in the keystores (AWS ACM delete; Azure Key Vault delete and purge), then the keystores, then the cloud providers. Reports everything it could not remove and exits non-zero. |

`check` and `teardown` do nothing when setup did not run or was skipped.

## Safety rules

- **Only CI objects are touched.** Every cloud provider and keystore cloudci creates is named
  `vcert-ci-<unix time>-<run id>-<suffix>`. It never modifies or deletes anything else.
- **One run at a time per tenant.** A tenant allows only one cloud provider per AWS account and per Azure app, so
  two runs cannot both create theirs. When setup finds a CI cloud provider for a configured account:
  - younger than `-stale-after` (3 hours by default, longer than the job timeout): another run is in progress, so
    setup **skips**. It records the reason in the state file, exits 0, and check and teardown do nothing;
  - older: a run crashed without cleaning up, so setup removes it first.

  A run only skips before it has created anything. If another run takes an account after this one has created
  some of its cloud providers, setup fails instead, and teardown removes what it created. A configuration that
  lists the same AWS account or Azure app twice, or two keystores with the same region or key vault under one
  cloud provider, is rejected.
- **Accounts used by something else stop the run.** If a cloud provider that was not created by the CI already
  uses a configured account, setup fails with its name and does nothing. Removing such cloud providers is a
  one-time step when moving to CI-managed cloud providers.
- **Only provisioned certificates are deleted from the cloud.** Teardown deletes the certificates whose machine
  identity is `INSTALLED` (provisioned through the platform), never ones the platform only found in the keystore,
  and only from keystores configured with `canProvision`. An ACM certificate is only deleted when its ARN is in
  the keystore's region and the configured account.
- **The state file must belong to this run.** Setup replaces it before doing anything else. Check and teardown
  refuse a state file written for another target or run ID (`-run-id`, the Jenkins `BUILD_NUMBER` by default),
  and teardown only deletes a cloud provider whose current name is still a CI name.
- **No secrets in the state file.** It holds names, IDs and non-secret settings only.

## Connection

| Target | Environment variables |
|---|---|
| `vcp` | `CLOUD_APIKEY`; `CLOUD_URL` for a platform other than production (`https://api.venafi.cloud`) |
| `ngts` | `NGTS_URL`, `NGTS_TOKEN_URL`, `NGTS_CLIENT_ID`, `NGTS_CLIENT_SECRET`, `NGTS_SCOPE` |

These are the same variables the vcert integration tests use.

## Configuration files

Both files may contain `"$comment"` keys anywhere; they are ignored. Unknown keys are ignored too.

### `aws_crud.json`

```json
{
  "owningTeamName": "DevOpsTeam",
  "cloudProviders": [
    {
      "awsAccountId": "123456789012",
      "awsIamRoleName": "role-name",
      "awsAccessKeyId": "AKIA...",
      "awsSecretAccessKeyJenkinsCredentialId": "vcert-aws-crud-secret-access-key-01",
      "cloudKeystores": [
        { "awsRegion": "us-east-2", "canProvision": true }
      ]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `owningTeamName` | Team that owns the cloud providers and keystores on CyberArk Certificate Manager, SaaS, where one is required. Not used on NGTS. |
| `awsAccountId` | 12-digit AWS account the cloud provider connects to. |
| `awsIamRoleName` | IAM role the platform assumes in that account. Its trust policy must allow the platform. |
| `awsAccessKeyId`, `awsSecretAccessKey` | Access key used only to delete provisioned certificates from ACM. Required when a keystore has `canProvision`. Leave the secret out of the file; see Secrets. |
| `awsSecretAccessKeyJenkinsCredentialId` | Jenkins "Secret text" credential holding the secret access key. Read by the pipeline, not by cloudci. |
| `awsRegion` | Region of the ACM keystore. A cloud provider cannot have two keystores with the same configuration. |
| `canProvision` | The tests may provision certificates to this keystore, and the access key may delete them: `acm:ImportCertificate` for the platform's role, `acm:DeleteCertificate` for the access key. |

### `azure_crud.json`

```json
{
  "owningTeamName": "DevOpsTeam",
  "cloudProviders": [
    {
      "clientId": "00000000-0000-0000-0000-000000000000",
      "tenantId": "00000000-0000-0000-0000-000000000000",
      "clientSecretExpires": "2027-01-31",
      "clientSecretJenkinsCredentialId": "vcert-azure-crud-client-secret-01",
      "cloudKeystores": [
        { "keyVaultName": "vcert-auto-do-not-delete", "canProvision": true },
        { "keyVaultName": "vaas-auto-do-not-delete", "canProvision": false }
      ]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `owningTeamName` | As for AWS. |
| `clientId`, `tenantId` | Azure app (service principal) the cloud provider connects with. It must not be used by any other cloud provider in the tenant. |
| `clientSecret` | The app's client secret. Leave it out of the file; see Secrets. |
| `clientSecretExpires` | Expiry date of the secret (`YYYY-MM-DD`). cloudci fails with a clear message once it has passed, and warns two weeks before. |
| `clientSecretJenkinsCredentialId` | Jenkins "Secret text" credential holding the client secret. Read by the pipeline, not by cloudci. |
| `keyVaultName` | Key vault of the AKV keystore. |
| `canProvision` | The tests may provision certificates to this vault, and cloudci may delete and purge them. The app needs to list, read, import, delete and purge certificates and read their secrets (for example Key Vault Certificates Officer and Key Vault Secrets User), and Reader on the subscription. The vault must use Azure role-based access control, and purge protection must be off. |

A keystore without `canProvision` only needs the app to list and read certificates and their secrets.

### Secrets

Secrets missing from the files are read from environment variables named after the cloud provider's position in
the file, starting at 0:

| Secret | Variable |
|---|---|
| AWS secret access key of `cloudProviders[n]` | `AWS_CRUD_SECRET_ACCESS_KEY_<n>` |
| Azure client secret of `cloudProviders[n]` | `AZURE_CRUD_CLIENT_SECRET_<n>` |

The Jenkins pipeline binds these from the credentials named by the `…JenkinsCredentialId` fields.

## State file

Written by setup and read by check and teardown. `env` holds what the provisioning tests (aruba) read to find the
keystores to provision to, for the first keystore of each cloud with `canProvision`:
`AWS_PROVIDER_NAME`, `AWS_KEYSTORE_NAME`, `AWS_KEYSTORE_ID`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`,
`AZURE_PROVIDER_NAME`, `AZURE_KEYSTORE_NAME`, `AZURE_KEYSTORE_ID`, `AZURE_KEYVAULT_NAME`, `AZURE_CLIENT_ID`,
`AZURE_TENANT_ID`, plus `AWS_CRUD_PROVIDER_INDEX` and `AZURE_CRUD_PROVIDER_INDEX`, which tell the pipeline which
secret variables to pass on as `AWS_SECRET_ACCESS_KEY` and `AZURE_CLIENT_SECRET`.
