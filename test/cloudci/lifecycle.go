/*
 * Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

type cloudManager interface {
	endpoint.CloudProviderManager
	endpoint.CloudKeystoreManager
}

type certCleaner interface {
	deleteACMCertificate(arn string, region string, accessKeyID string, secretAccessKey string) error
	deleteAzureCertificate(vault string, name string, tenantID string, clientID string, clientSecret string) error
}

// lifecycle creates the cloud providers and keystores described by the CRUD
// configuration in one tenant, checks the CRUD operations on them, and
// deletes them again.
type lifecycle struct {
	target  string
	runID   string
	aws     *awsCRUDConfig
	azure   *azureCRUDConfig
	manager cloudManager
	cleaner certCleaner
	now     func() time.Time

	// staleAfter is the age after which CI objects are considered left behind
	// by a run that did not clean up; younger ones belong to a run in progress
	staleAfter         time.Duration
	validationTimeout  time.Duration
	validationInterval time.Duration
	// retryInterval is the wait between attempts of a request that failed
	retryInterval time.Duration
}

// errSkipped is returned by setup when another run is using the cloud accounts
var errSkipped = errors.New("skipped")

// desiredProvider is a cloud provider the configuration asks for
type desiredProvider struct {
	kind        string
	configIndex int
	describe    string
	matches     func(domain.CloudProvider) bool
	request     func(name string) domain.CreateCloudProviderRequest
	keystores   []desiredKeystore
}

type desiredKeystore struct {
	location     string
	canProvision bool
	request      func(name string, providerID string) domain.CreateCloudKeystoreRequest
}

// team returns the owning team for the objects the lifecycle creates. Only
// CyberArk Certificate Manager, SaaS requires one; NGTS has no team names.
func (l *lifecycle) team() string {
	if l.target != targetVCP {
		return ""
	}
	if l.aws != nil && l.aws.OwningTeamName != "" {
		return l.aws.OwningTeamName
	}
	if l.azure != nil {
		return l.azure.OwningTeamName
	}
	return ""
}

func (l *lifecycle) desiredProviders() []desiredProvider {
	team := l.team()
	var desired []desiredProvider
	if l.aws != nil {
		for i, p := range l.aws.CloudProviders {
			d := desiredProvider{
				kind:        kindAWS,
				configIndex: i,
				describe:    "AWS account " + p.AccountID,
				matches: func(cp domain.CloudProvider) bool {
					return cp.Type == domain.CloudProviderTypeAWS && cp.AWS != nil && cp.AWS.AccountID == p.AccountID
				},
				request: func(name string) domain.CreateCloudProviderRequest {
					return domain.CreateCloudProviderRequest{
						Name: name, Type: domain.CloudProviderTypeAWS, TeamID: team,
						AWS: &domain.CloudProviderAWSConfiguration{AccountID: p.AccountID, Role: p.IAMRoleName},
					}
				},
			}
			for _, k := range p.CloudKeystores {
				d.keystores = append(d.keystores, desiredKeystore{
					location: k.Region, canProvision: k.CanProvision,
					request: func(name string, providerID string) domain.CreateCloudKeystoreRequest {
						return domain.CreateCloudKeystoreRequest{
							Name: name, Type: domain.CloudKeystoreTypeACM, CloudProviderID: providerID, TeamID: team,
							ACM: &domain.CloudKeystoreACMConfiguration{Region: k.Region},
						}
					},
				})
			}
			desired = append(desired, d)
		}
	}
	if l.azure != nil {
		for i, p := range l.azure.CloudProviders {
			d := desiredProvider{
				kind:        kindAzure,
				configIndex: i,
				describe:    "Azure app " + p.ClientID,
				matches: func(cp domain.CloudProvider) bool {
					return cp.Type == domain.CloudProviderTypeAzure && cp.Azure != nil &&
						cp.Azure.ApplicationID == p.ClientID && cp.Azure.DirectoryID == p.TenantID
				},
				request: func(name string) domain.CreateCloudProviderRequest {
					return domain.CreateCloudProviderRequest{
						Name: name, Type: domain.CloudProviderTypeAzure, TeamID: team,
						Azure: &domain.CloudProviderAzureConfiguration{ApplicationID: p.ClientID, DirectoryID: p.TenantID, Secret: p.ClientSecret},
					}
				},
			}
			for _, k := range p.CloudKeystores {
				d.keystores = append(d.keystores, desiredKeystore{
					location: k.KeyVaultName, canProvision: k.CanProvision,
					request: func(name string, providerID string) domain.CreateCloudKeystoreRequest {
						return domain.CreateCloudKeystoreRequest{
							Name: name, Type: domain.CloudKeystoreTypeAKV, CloudProviderID: providerID, TeamID: team,
							AKV: &domain.CloudKeystoreAKVConfiguration{KeyVaultName: k.KeyVaultName},
						}
					},
				})
			}
			desired = append(desired, d)
		}
	}
	return desired
}

// setup creates and validates the cloud providers, then creates their
// keystores. It records everything it creates in st as it goes, so that
// teardown can remove a partial setup. It returns errSkipped, with nothing
// created, when another run is using the same cloud accounts.
func (l *lifecycle) setup(st *state, save func() error) error {
	desired := l.desiredProviders()
	if len(desired) == 0 {
		return errors.New("the configuration has no cloud providers")
	}
	if l.target == targetVCP && l.team() == "" {
		return errors.New("owningTeamName is required in the configuration for CyberArk Certificate Manager, SaaS")
	}

	existing, err := l.manager.ListCloudProviders(domain.GetCloudProviderRequest{})
	if err != nil {
		return err
	}

	// First decide, without changing anything, whether this run may proceed
	type staleProvider struct {
		provider domain.CloudProvider
		desired  desiredProvider
	}
	var stale []staleProvider
	for _, d := range desired {
		for _, cp := range existing {
			if !d.matches(cp) {
				continue
			}
			created, isCI := ciCreated(cp.Name)
			if !isCI {
				return fmt.Errorf("cloud provider %q (ID %s) already uses %s in this tenant, and it was not created by the CI. "+
					"A tenant allows only one cloud provider per cloud account, so remove it (a one-time step when moving to "+
					"CI-managed cloud providers) or configure another account", cp.Name, cp.ID, d.describe)
			}
			if l.now().Sub(created) < l.staleAfter {
				st.Skipped = true
				st.SkipReason = fmt.Sprintf("cloud provider %q for %s belongs to a run started at %s that may still be in progress",
					cp.Name, d.describe, created.UTC().Format(time.RFC3339))
				return errSkipped
			}
			stale = append(stale, staleProvider{provider: cp, desired: d})
		}
	}

	for _, s := range stale {
		logf("removing cloud provider %q left behind by an earlier run", s.provider.Name)
		if err := l.removeProvider(s.provider.ID, s.desired); err != nil {
			return fmt.Errorf("cannot remove cloud provider %q left behind by an earlier run: %w", s.provider.Name, err)
		}
	}

	created := l.now()
	for _, d := range desired {
		name := ciName(created, l.runID, d.kind+strconv.Itoa(d.configIndex+1))
		cp, err := l.manager.CreateCloudProvider(d.request(name))
		if err != nil {
			if l.otherRunCreated(d, st) {
				reason := fmt.Sprintf("another run created a cloud provider for %s at the same time", d.describe)
				// a skipped run is not torn down, so it may only skip
				// before creating anything
				if len(st.Providers) > 0 {
					return fmt.Errorf("%s; teardown removes what this run created", reason)
				}
				st.Skipped = true
				st.SkipReason = reason
				return errSkipped
			}
			return fmt.Errorf("cannot create the cloud provider for %s: %w", d.describe, err)
		}
		logf("created cloud provider %q (ID %s) for %s", cp.Name, cp.ID, d.describe)
		st.Providers = append(st.Providers, providerState{ID: cp.ID, Name: cp.Name, Kind: d.kind, ConfigIndex: d.configIndex})
		if err := save(); err != nil {
			return err
		}
	}

	for _, p := range st.Providers {
		if err := l.validate(p); err != nil {
			return err
		}
	}

	for i, d := range desired {
		providerID := st.Providers[i].ID
		for j, k := range d.keystores {
			name := ciName(created, l.runID, fmt.Sprintf("%s%d-ks%d", d.kind, d.configIndex+1, j+1))
			ks, err := l.manager.CreateCloudKeystore(k.request(name, providerID))
			if err != nil {
				return fmt.Errorf("cannot create the cloud keystore for %s in %s: %w", k.location, d.describe, err)
			}
			logf("created cloud keystore %q (ID %s) for %s", ks.Name, ks.ID, k.location)
			st.Keystores = append(st.Keystores, keystoreState{
				ID: ks.ID, Name: ks.Name, Kind: d.kind, ProviderID: providerID,
				ConfigIndex: d.configIndex, CanProvision: k.canProvision, Location: k.location,
			})
			if err := save(); err != nil {
				return err
			}
		}
	}

	st.Env = l.provisioningEnv(st)
	return save()
}

// otherRunCreated reports whether a CI cloud provider for the account that
// this run did not create now exists, as when another run created one between
// our listing and creating
func (l *lifecycle) otherRunCreated(d desiredProvider, st *state) bool {
	providers, err := l.manager.ListCloudProviders(domain.GetCloudProviderRequest{})
	if err != nil {
		return false
	}
	ours := map[string]bool{}
	for _, p := range st.Providers {
		ours[p.ID] = true
	}
	for _, cp := range providers {
		if _, isCI := ciCreated(cp.Name); isCI && d.matches(cp) && !ours[cp.ID] {
			return true
		}
	}
	return false
}

// validate validates a cloud provider, retrying while cloud IAM changes
// propagate
func (l *lifecycle) validate(p providerState) error {
	deadline := l.now().Add(l.validationTimeout)
	for {
		result, err := l.manager.ValidateCloudProvider(p.ID)
		if err != nil {
			return fmt.Errorf("cannot validate cloud provider %q: %w", p.Name, err)
		}
		if result.Status == domain.CloudProviderStatusValidated {
			logf("validated cloud provider %q", p.Name)
			return nil
		}
		if l.now().Add(l.validationInterval).After(deadline) {
			return fmt.Errorf("cloud provider %q was not validated within %s: %s", p.Name, l.validationTimeout, result.Details)
		}
		logf("cloud provider %q not validated yet (%s); retrying", p.Name, result.Details)
		time.Sleep(l.validationInterval)
	}
}

// provisioningEnv returns the variables the provisioning tests read, for the
// first keystore of each cloud that may be provisioned to. Secrets are not
// included: the pipeline adds them from the credentials.
func (l *lifecycle) provisioningEnv(st *state) map[string]string {
	env := map[string]string{}
	providerName := map[string]string{}
	for _, p := range st.Providers {
		providerName[p.ID] = p.Name
	}
	for _, k := range st.Keystores {
		if !k.CanProvision {
			continue
		}
		switch {
		case k.Kind == kindAWS && env["AWS_KEYSTORE_ID"] == "":
			p := l.aws.CloudProviders[k.ConfigIndex]
			env["AWS_PROVIDER_NAME"] = providerName[k.ProviderID]
			env["AWS_KEYSTORE_NAME"] = k.Name
			env["AWS_KEYSTORE_ID"] = k.ID
			env["AWS_REGION"] = k.Location
			env["AWS_ACCESS_KEY_ID"] = p.AccessKeyID
			env["AWS_CRUD_PROVIDER_INDEX"] = strconv.Itoa(k.ConfigIndex)
		case k.Kind == kindAzure && env["AZURE_KEYSTORE_ID"] == "":
			p := l.azure.CloudProviders[k.ConfigIndex]
			env["AZURE_PROVIDER_NAME"] = providerName[k.ProviderID]
			env["AZURE_KEYSTORE_NAME"] = k.Name
			env["AZURE_KEYSTORE_ID"] = k.ID
			env["AZURE_KEYVAULT_NAME"] = k.Location
			env["AZURE_CLIENT_ID"] = p.ClientID
			env["AZURE_TENANT_ID"] = p.TenantID
			env["AZURE_CRUD_PROVIDER_INDEX"] = strconv.Itoa(k.ConfigIndex)
		}
	}
	return env
}

// teardown deletes the certificates provisioned to the keystores setup
// created, then the keystores, then the cloud providers. It carries on after
// errors and returns all of them, so that as much as possible is removed.
func (l *lifecycle) teardown(st *state) error {
	if st == nil || st.Skipped {
		return nil
	}
	desired := l.desiredProviders()
	existing, err := l.listProvidersWithRetry()
	if err != nil {
		return err
	}
	current := map[string]string{}
	for _, cp := range existing {
		current[cp.ID] = cp.Name
	}
	var errs []error
	for i := len(st.Providers) - 1; i >= 0; i-- {
		p := st.Providers[i]
		name, exists := current[p.ID]
		if !exists {
			logf("cloud provider %q is already gone", p.Name)
			continue
		}
		// the IDs come from a file, so check that they still name CI objects
		if _, isCI := ciCreated(name); !isCI {
			errs = append(errs, fmt.Errorf("cloud provider %s is now named %q, which was not created by the CI; not deleting it", p.ID, name))
			continue
		}
		d, ok := findDesired(desired, p.Kind, p.ConfigIndex)
		if !ok {
			errs = append(errs, fmt.Errorf("cloud provider %q is not in the configuration any more; delete it by hand", p.Name))
			continue
		}
		if err := l.removeProvider(p.ID, d); err != nil {
			errs = append(errs, fmt.Errorf("cloud provider %q: %w", p.Name, err))
			continue
		}
		logf("deleted cloud provider %q", p.Name)
	}
	return errors.Join(errs...)
}

// listProvidersWithRetry lists the cloud providers, retrying a few times so
// that a transient failure does not stop teardown before it deleted anything
func (l *lifecycle) listProvidersWithRetry() ([]domain.CloudProvider, error) {
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		var providers []domain.CloudProvider
		if providers, err = l.manager.ListCloudProviders(domain.GetCloudProviderRequest{}); err == nil {
			return providers, nil
		}
		logf("cannot list cloud providers (attempt %d of 3): %s", attempt, err)
		time.Sleep(l.retryInterval)
	}
	return nil, err
}

func findDesired(desired []desiredProvider, kind string, configIndex int) (desiredProvider, bool) {
	for _, d := range desired {
		if d.kind == kind && d.configIndex == configIndex {
			return d, true
		}
	}
	return desiredProvider{}, false
}

// removeProvider deletes a CI cloud provider: first the certificates
// provisioned to its keystores, then the keystores, then the provider. It
// refuses to delete keystores that were not created by the CI.
func (l *lifecycle) removeProvider(providerID string, d desiredProvider) error {
	keystores, err := l.manager.ListCloudKeystores(domain.GetCloudKeystoreRequest{CloudProviderID: &providerID})
	if err != nil {
		return err
	}
	var errs []error
	for _, ks := range keystores {
		if ks.CloudProviderID != "" && ks.CloudProviderID != providerID {
			continue
		}
		if _, isCI := ciCreated(ks.Name); !isCI {
			errs = append(errs, fmt.Errorf("keystore %q (ID %s) was not created by the CI; delete it by hand", ks.Name, ks.ID))
			continue
		}
		if err := l.deleteProvisionedCertificates(ks, d); err != nil {
			errs = append(errs, fmt.Errorf("keystore %q: %w", ks.Name, err))
			continue
		}
		if err := l.manager.DeleteCloudKeystore(ks.ID); err != nil {
			errs = append(errs, fmt.Errorf("cannot delete keystore %q: %w", ks.Name, err))
			continue
		}
		logf("deleted cloud keystore %q", ks.Name)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return l.manager.DeleteCloudProvider(providerID)
}

// canProvision reports whether the configuration lets the tests provision to
// a keystore, found by its region or key vault
func (d desiredProvider) canProvision(ks domain.CloudKeystore) bool {
	location := ""
	switch {
	case ks.ACM != nil:
		location = ks.ACM.Region
	case ks.AKV != nil:
		location = ks.AKV.KeyVaultName
	}
	for _, k := range d.keystores {
		if k.canProvision && location != "" && k.location == location {
			return true
		}
	}
	return false
}

// deleteProvisionedCertificates deletes from the cloud the certificates the
// platform installed in a keystore the tests may provision to. Certificates
// the platform only found in the keystore are left alone: they were not
// created by the tests. So are all certificates in keystores the tests may
// not provision to.
func (l *lifecycle) deleteProvisionedCertificates(ks domain.CloudKeystore, d desiredProvider) error {
	identities, err := l.manager.ListMachineIdentities(domain.ListCloudMachineIdentitiesRequest{KeystoreID: ks.ID})
	if !d.canProvision(ks) {
		// Nothing is deleted from such a keystore, so a failed listing only
		// loses the warnings below; it must not keep the keystore
		if err != nil {
			logf("WARNING: cannot list the machine identities of keystore %q to report certificates left in the cloud: %s", ks.Name, err)
			return nil
		}
		// As when a crashed run's keystore is no longer configured to
		// provision. Its certificates stay in the cloud; say so.
		for _, mi := range identities {
			if mi.Status == domain.MachineIdentityStatusInstalled {
				logf("WARNING: not deleting certificate %s from keystore %q, which is not configured with canProvision; it stays in the cloud",
					certificateLocation(mi), ks.Name)
			}
		}
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, mi := range identities {
		if mi.Status != domain.MachineIdentityStatusInstalled || mi.Metadata == nil {
			continue
		}
		switch d.kind {
		case kindAWS:
			p := l.aws.CloudProviders[d.configIndex]
			arn, _ := mi.Metadata.GetValue("arn").(string)
			if arn == "" || ks.ACM == nil {
				continue
			}
			// only certificates in the keystore's own region and account
			region, account, err := parseCertificateARN(arn)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if region != ks.ACM.Region || account != p.AccountID {
				errs = append(errs, fmt.Errorf("not deleting certificate %s: it is not in region %s of account %s", arn, ks.ACM.Region, p.AccountID))
				continue
			}
			if err := l.cleaner.deleteACMCertificate(arn, ks.ACM.Region, p.AccessKeyID, p.SecretAccessKey); err != nil {
				errs = append(errs, err)
				continue
			}
			logf("deleted provisioned certificate %s from ACM", arn)
		case kindAzure:
			p := l.azure.CloudProviders[d.configIndex]
			name, _ := mi.Metadata.GetValue("name").(string)
			if name == "" || ks.AKV == nil {
				continue
			}
			if err := l.cleaner.deleteAzureCertificate(ks.AKV.KeyVaultName, name, p.TenantID, p.ClientID, p.ClientSecret); err != nil {
				errs = append(errs, err)
				continue
			}
			logf("deleted and purged provisioned certificate %s from key vault %s", name, ks.AKV.KeyVaultName)
		}
	}
	return errors.Join(errs...)
}

// certificateLocation describes where a machine identity's certificate is in
// the cloud
func certificateLocation(mi domain.CloudMachineIdentity) string {
	if mi.Metadata != nil {
		for _, key := range []string{"arn", "name"} {
			if v, _ := mi.Metadata.GetValue(key).(string); v != "" {
				return v
			}
		}
	}
	return "of machine identity " + mi.ID
}
