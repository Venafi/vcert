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
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Venafi/vcert/v5/pkg/domain"
)

func init() {
	logOutput = io.Discard
}

// fakePlatform is an in-memory cloud providers service that enforces the
// rules of the real one: one cloud provider per AWS account or Azure app,
// unique keystore names and configurations, no deleting a cloud provider that
// has keystores, and a keystore update that keeps unchanged discovery settings
type fakePlatform struct {
	providers  map[string]*domain.CloudProvider
	keystores  map[string]*domain.CloudKeystore
	identities map[string][]domain.CloudMachineIdentity
	teams      []string
	nextID     int

	validationResults []domain.CloudProviderValidationResult
	validateCalls     int
	// beforeCreate runs at the start of CreateCloudProvider, to simulate
	// another run creating a cloud provider at the same time
	beforeCreate func()
}

func newFakePlatform() *fakePlatform {
	return &fakePlatform{
		providers:  map[string]*domain.CloudProvider{},
		keystores:  map[string]*domain.CloudKeystore{},
		identities: map[string][]domain.CloudMachineIdentity{},
	}
}

func (f *fakePlatform) id() string {
	f.nextID++
	return fmt.Sprintf("id-%d", f.nextID)
}

func (f *fakePlatform) ListCloudProviders(filter domain.GetCloudProviderRequest) ([]domain.CloudProvider, error) {
	var result []domain.CloudProvider
	for _, p := range f.providers {
		if filter.Name == "" || p.Name == filter.Name {
			result = append(result, *p)
		}
	}
	return result, nil
}

func (f *fakePlatform) addProvider(p domain.CloudProvider) *domain.CloudProvider {
	if p.ID == "" {
		p.ID = f.id()
	}
	f.providers[p.ID] = &p
	return &p
}

func (f *fakePlatform) CreateCloudProvider(r domain.CreateCloudProviderRequest) (*domain.CloudProvider, error) {
	if f.beforeCreate != nil {
		f.beforeCreate()
	}
	for _, p := range f.providers {
		if r.AWS != nil && p.AWS != nil && p.AWS.AccountID == r.AWS.AccountID {
			return nil, errors.New("cannot create duplicated AWS Account ID")
		}
		if r.Azure != nil && p.Azure != nil && p.Azure.ApplicationID == r.Azure.ApplicationID {
			return nil, errors.New("cannot create duplicated Azure application id")
		}
	}
	f.teams = append(f.teams, r.TeamID)
	p := domain.CloudProvider{Name: r.Name, Type: r.Type, Status: domain.CloudProviderStatusNotValidated}
	if r.AWS != nil {
		p.AWS = &domain.CloudProviderAWSConfiguration{AccountID: r.AWS.AccountID, Role: r.AWS.Role, ExternalID: "ext"}
	}
	if r.Azure != nil {
		p.Azure = &domain.CloudProviderAzureConfiguration{ApplicationID: r.Azure.ApplicationID, DirectoryID: r.Azure.DirectoryID}
	}
	return f.addProvider(p), nil
}

func (f *fakePlatform) UpdateCloudProvider(r domain.UpdateCloudProviderRequest) (*domain.CloudProvider, error) {
	p, ok := f.providers[r.ID]
	if !ok {
		return nil, errors.New("not found")
	}
	if r.Name != nil {
		p.Name = *r.Name
	}
	copied := *p
	return &copied, nil
}

func (f *fakePlatform) DeleteCloudProvider(id string) error {
	if _, ok := f.providers[id]; !ok {
		return errors.New("not found")
	}
	for _, k := range f.keystores {
		if k.CloudProviderID == id {
			return errors.New("cloud provider is associated with active cloud keystores")
		}
	}
	delete(f.providers, id)
	return nil
}

func (f *fakePlatform) ValidateCloudProvider(id string) (*domain.CloudProviderValidationResult, error) {
	result := domain.CloudProviderValidationResult{Status: domain.CloudProviderStatusValidated}
	if len(f.validationResults) > 0 {
		i := f.validateCalls
		if i >= len(f.validationResults) {
			i = len(f.validationResults) - 1
		}
		result = f.validationResults[i]
	}
	f.validateCalls++
	f.providers[id].Status = result.Status
	return &result, nil
}

func (f *fakePlatform) ListCloudKeystores(filter domain.GetCloudKeystoreRequest) ([]domain.CloudKeystore, error) {
	var result []domain.CloudKeystore
	for _, k := range f.keystores {
		if filter.CloudKeystoreID != nil && *filter.CloudKeystoreID != k.ID {
			continue
		}
		if filter.CloudProviderID != nil && *filter.CloudProviderID != k.CloudProviderID {
			continue
		}
		copied := *k
		if k.DiscoveryConfiguration != nil {
			dc := *k.DiscoveryConfiguration
			copied.DiscoveryConfiguration = &dc
		}
		result = append(result, copied)
	}
	return result, nil
}

func (f *fakePlatform) addKeystore(k domain.CloudKeystore) *domain.CloudKeystore {
	if k.ID == "" {
		k.ID = f.id()
	}
	if k.DiscoveryConfiguration == nil {
		k.DiscoveryConfiguration = &domain.CloudDiscoveryConfiguration{}
	}
	f.keystores[k.ID] = &k
	return &k
}

func (f *fakePlatform) CreateCloudKeystore(r domain.CreateCloudKeystoreRequest) (*domain.CloudKeystore, error) {
	if p, ok := f.providers[r.CloudProviderID]; !ok || p.Status != domain.CloudProviderStatusValidated {
		return nil, errors.New("cloud provider is not validated")
	}
	for _, k := range f.keystores {
		if k.Name == r.Name {
			return nil, errors.New("cloud keystore already exists (same name)")
		}
		if k.CloudProviderID == r.CloudProviderID && fmt.Sprint(k.ACM, k.AKV) == fmt.Sprint(r.ACM, r.AKV) {
			return nil, errors.New("cloud keystore already exists (same configuration)")
		}
	}
	return f.addKeystore(domain.CloudKeystore{Name: r.Name, Type: r.Type, CloudProviderID: r.CloudProviderID, ACM: r.ACM, AKV: r.AKV}), nil
}

func (f *fakePlatform) UpdateCloudKeystore(r domain.UpdateCloudKeystoreRequest) (*domain.CloudKeystore, error) {
	k, ok := f.keystores[r.ID]
	if !ok {
		return nil, errors.New("not found")
	}
	if r.Name != nil {
		k.Name = *r.Name
	}
	if d := r.Discovery; d != nil {
		if d.ScheduleSpecification != nil {
			k.DiscoveryConfiguration.ScheduleSpecification = *d.ScheduleSpecification
		}
		if d.IncludeExpiredCertificates != nil {
			k.DiscoveryConfiguration.IncludeExpiredCertificates = *d.IncludeExpiredCertificates
		}
		if d.IncludeRevokedCertificates != nil {
			k.DiscoveryConfiguration.IncludeRevokedCertificates = *d.IncludeRevokedCertificates
		}
	}
	copied := *k
	return &copied, nil
}

func (f *fakePlatform) DeleteCloudKeystore(id string) error {
	if _, ok := f.keystores[id]; !ok {
		return errors.New("not found")
	}
	delete(f.keystores, id)
	delete(f.identities, id)
	return nil
}

func (f *fakePlatform) ListMachineIdentities(r domain.ListCloudMachineIdentitiesRequest) ([]domain.CloudMachineIdentity, error) {
	return f.identities[r.KeystoreID], nil
}

type fakeCleaner struct {
	deletedARNs  []string
	deletedAzure []string
	err          error
}

func (c *fakeCleaner) deleteACMCertificate(arn string, region string, accessKeyID string, secretAccessKey string) error {
	if c.err != nil {
		return c.err
	}
	if accessKeyID == "" || secretAccessKey == "" {
		return errors.New("missing AWS credentials")
	}
	c.deletedARNs = append(c.deletedARNs, region+"|"+arn)
	return nil
}

func (c *fakeCleaner) deleteAzureCertificate(vault string, name string, tenantID string, clientID string, clientSecret string) error {
	if c.err != nil {
		return c.err
	}
	if clientSecret == "" {
		return errors.New("missing Azure secret")
	}
	c.deletedAzure = append(c.deletedAzure, vault+"/"+name)
	return nil
}

var testNow = time.Date(2026, 11, 12, 9, 40, 0, 0, time.UTC)

func newTestLifecycle(target string, platform *fakePlatform, cleaner *fakeCleaner) *lifecycle {
	return &lifecycle{
		target:  target,
		runID:   "42",
		manager: platform,
		cleaner: cleaner,
		now:     func() time.Time { return testNow },
		aws: &awsCRUDConfig{
			OwningTeamName: "DevOpsTeam",
			CloudProviders: []awsProviderEntry{{
				AccountID: "123456789012", IAMRoleName: "ci-role", AccessKeyID: "AKIA1", SecretAccessKey: "aws-secret",
				CloudKeystores: []awsKeystoreEntry{{Region: "us-east-2", CanProvision: true}},
			}},
		},
		azure: &azureCRUDConfig{
			OwningTeamName: "DevOpsTeam",
			CloudProviders: []azureProviderEntry{{
				ClientID: "app-1", TenantID: "tenant-1", ClientSecret: "azure-secret",
				CloudKeystores: []azureKeystoreEntry{
					{KeyVaultName: "vcert-auto-do-not-delete", CanProvision: true},
					{KeyVaultName: "vaas-auto-do-not-delete", CanProvision: false},
				},
			}},
		},
		staleAfter:         3 * time.Hour,
		validationTimeout:  time.Second,
		validationInterval: time.Millisecond,
	}
}

func runSetup(t *testing.T, l *lifecycle) (*state, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	st := &state{Target: l.target, RunID: l.runID}
	err := l.setup(st, func() error { return st.save(path) })
	saved, loadErr := loadState(path)
	if loadErr != nil {
		t.Fatalf("cannot load the saved state: %s", loadErr)
	}
	if saved == nil && err == nil {
		t.Fatalf("setup did not save its state")
	}
	return st, err
}

func TestSetupCreatesValidatesAndRecords(t *testing.T) {
	platform := newFakePlatform()
	platform.validationResults = []domain.CloudProviderValidationResult{
		{Status: domain.CloudProviderStatusNotValidated, Details: "role cannot be assumed"},
		{Status: domain.CloudProviderStatusValidated},
	}
	l := newTestLifecycle(targetVCP, platform, &fakeCleaner{})

	st, err := runSetup(t, l)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}
	if len(st.Providers) != 2 || len(st.Keystores) != 3 {
		t.Fatalf("unexpected state: %+v", st)
	}
	for _, p := range st.Providers {
		if !strings.HasPrefix(p.Name, "vcert-ci-") || !strings.Contains(p.Name, "-42-") {
			t.Fatalf("unexpected provider name %q", p.Name)
		}
		if platform.providers[p.ID].Status != domain.CloudProviderStatusValidated {
			t.Fatalf("provider %q was not validated", p.Name)
		}
	}
	for _, team := range platform.teams {
		if team != "DevOpsTeam" {
			t.Fatalf("expected the owning team on VCP, got %q", team)
		}
	}
	// the provisioning tests get the keystores that may be provisioned to
	if st.Env["AWS_KEYSTORE_ID"] == "" || st.Env["AWS_REGION"] != "us-east-2" || st.Env["AWS_ACCESS_KEY_ID"] != "AKIA1" {
		t.Fatalf("unexpected AWS environment: %v", st.Env)
	}
	if st.Env["AZURE_KEYVAULT_NAME"] != "vcert-auto-do-not-delete" || st.Env["AZURE_CLIENT_ID"] != "app-1" {
		t.Fatalf("expected the Azure keystore that can provision, got %v", st.Env)
	}
	for _, v := range st.Env {
		if v == "aws-secret" || v == "azure-secret" {
			t.Fatalf("a secret leaked into the state: %v", st.Env)
		}
	}
}

func TestSetupOnNGTSUsesNoTeam(t *testing.T) {
	platform := newFakePlatform()
	l := newTestLifecycle(targetNGTS, platform, &fakeCleaner{})
	if _, err := runSetup(t, l); err != nil {
		t.Fatalf("setup failed: %s", err)
	}
	for _, team := range platform.teams {
		if team != "" {
			t.Fatalf("expected no team on NGTS, got %q", team)
		}
	}
}

func TestSetupRequiresTeamOnVCP(t *testing.T) {
	l := newTestLifecycle(targetVCP, newFakePlatform(), &fakeCleaner{})
	l.aws.OwningTeamName, l.azure.OwningTeamName = "", ""
	if _, err := runSetup(t, l); err == nil || !strings.Contains(err.Error(), "owningTeamName") {
		t.Fatalf("expected a missing team error, got %v", err)
	}
}

func TestSetupSkipsWhenAnotherRunIsActive(t *testing.T) {
	platform := newFakePlatform()
	platform.addProvider(domain.CloudProvider{
		Name: ciName(testNow.Add(-30*time.Minute), "41", "aws1"), Type: domain.CloudProviderTypeAWS,
		AWS: &domain.CloudProviderAWSConfiguration{AccountID: "123456789012"},
	})
	l := newTestLifecycle(targetVCP, platform, &fakeCleaner{})

	st, err := runSetup(t, l)
	if !errors.Is(err, errSkipped) || !st.Skipped || !strings.Contains(st.SkipReason, "may still be in progress") {
		t.Fatalf("expected a skip, got %v (%+v)", err, st)
	}
	if len(platform.providers) != 1 || len(st.Providers) != 0 {
		t.Fatalf("expected nothing to be created, got %d providers", len(platform.providers))
	}
}

func TestSetupRemovesWhatAStaleRunLeftBehind(t *testing.T) {
	platform := newFakePlatform()
	cleaner := &fakeCleaner{}
	old := platform.addProvider(domain.CloudProvider{
		Name: ciName(testNow.Add(-5*time.Hour), "40", "aws1"), Type: domain.CloudProviderTypeAWS,
		Status: domain.CloudProviderStatusValidated,
		AWS:    &domain.CloudProviderAWSConfiguration{AccountID: "123456789012"},
	})
	ks := platform.addKeystore(domain.CloudKeystore{
		Name: ciName(testNow.Add(-5*time.Hour), "40", "aws1-ks1"), CloudProviderID: old.ID,
		ACM: &domain.CloudKeystoreACMConfiguration{Region: "us-east-2"},
	})
	installed := domain.NewCertificateCloudMetadata(map[string]interface{}{"arn": "arn:aws:acm:us-east-2:123456789012:certificate/1"})
	discovered := domain.NewCertificateCloudMetadata(map[string]interface{}{"arn": "arn:aws:acm:us-east-2:123456789012:certificate/2"})
	platform.identities[ks.ID] = []domain.CloudMachineIdentity{
		{ID: "m1", Status: domain.MachineIdentityStatusInstalled, Metadata: &installed},
		{ID: "m2", Status: domain.MachineIdentityStatusDiscovered, Metadata: &discovered},
	}
	l := newTestLifecycle(targetVCP, platform, cleaner)

	st, err := runSetup(t, l)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}
	if _, exists := platform.providers[old.ID]; exists {
		t.Fatalf("expected the stale provider to be removed")
	}
	// only the certificate the platform installed is deleted from the cloud
	if len(cleaner.deletedARNs) != 1 || cleaner.deletedARNs[0] != "us-east-2|arn:aws:acm:us-east-2:123456789012:certificate/1" {
		t.Fatalf("unexpected certificate deletions: %v", cleaner.deletedARNs)
	}
	if len(st.Providers) != 2 {
		t.Fatalf("expected new providers to be created, got %+v", st.Providers)
	}
}

func TestSetupRefusesAProviderNotCreatedByTheCI(t *testing.T) {
	platform := newFakePlatform()
	platform.addProvider(domain.CloudProvider{
		Name: "Production AWS", Type: domain.CloudProviderTypeAWS,
		AWS: &domain.CloudProviderAWSConfiguration{AccountID: "123456789012"},
	})
	l := newTestLifecycle(targetVCP, platform, &fakeCleaner{})

	_, err := runSetup(t, l)
	if err == nil || !strings.Contains(err.Error(), `"Production AWS"`) || !strings.Contains(err.Error(), "not created by the CI") {
		t.Fatalf("expected a refusal naming the provider, got %v", err)
	}
	if len(platform.providers) != 1 {
		t.Fatalf("expected nothing to be created or deleted")
	}
}

func TestSetupSkipsWhenAnotherRunCreatesAtTheSameTime(t *testing.T) {
	platform := newFakePlatform()
	platform.beforeCreate = func() {
		platform.beforeCreate = nil
		platform.addProvider(domain.CloudProvider{
			Name: ciName(testNow, "43", "aws1"), Type: domain.CloudProviderTypeAWS,
			AWS: &domain.CloudProviderAWSConfiguration{AccountID: "123456789012"},
		})
	}
	l := newTestLifecycle(targetVCP, platform, &fakeCleaner{})

	st, err := runSetup(t, l)
	if !errors.Is(err, errSkipped) || !strings.Contains(st.SkipReason, "at the same time") {
		t.Fatalf("expected a skip, got %v (%+v)", err, st)
	}
}

func TestSetupDoesNotSkipAfterCreatingSomething(t *testing.T) {
	platform := newFakePlatform()
	// another run creates a provider for the Azure app after this run
	// created its AWS provider
	platform.beforeCreate = func() {
		if len(platform.providers) == 0 {
			return
		}
		platform.beforeCreate = nil
		platform.addProvider(domain.CloudProvider{
			Name: ciName(testNow, "43", "azure1"), Type: domain.CloudProviderTypeAzure,
			Azure: &domain.CloudProviderAzureConfiguration{ApplicationID: "app-1", DirectoryID: "tenant-1"},
		})
	}
	l := newTestLifecycle(targetVCP, platform, &fakeCleaner{})

	st, err := runSetup(t, l)
	if err == nil || errors.Is(err, errSkipped) || st.Skipped || !strings.Contains(err.Error(), "at the same time") {
		t.Fatalf("expected a failure, not a skip, got %v (%+v)", err, st)
	}
	// the AWS provider is recorded, so that teardown removes it
	if len(st.Providers) != 1 || st.Providers[0].Kind != kindAWS {
		t.Fatalf("expected the AWS provider in the state, got %+v", st.Providers)
	}
	if err := l.teardown(st); err != nil {
		t.Fatalf("teardown failed: %s", err)
	}
	if _, exists := platform.providers[st.Providers[0].ID]; exists {
		t.Fatalf("expected the AWS provider to be removed")
	}
}

func TestSetupFailsWhenItsOwnProviderBlocksTheNext(t *testing.T) {
	platform := newFakePlatform()
	l := newTestLifecycle(targetVCP, platform, &fakeCleaner{})
	// two entries for the same account, which config loading rejects; the
	// lifecycle must still not mistake its own provider for another run's
	l.aws.CloudProviders = append(l.aws.CloudProviders, l.aws.CloudProviders[0])
	l.azure = nil

	st, err := runSetup(t, l)
	if err == nil || errors.Is(err, errSkipped) || st.Skipped {
		t.Fatalf("expected a failure, not a skip, got %v (%+v)", err, st)
	}
	if len(st.Providers) != 1 {
		t.Fatalf("expected the created provider in the state, got %+v", st.Providers)
	}
}

func TestSetupReportsValidationFailure(t *testing.T) {
	platform := newFakePlatform()
	platform.validationResults = []domain.CloudProviderValidationResult{
		{Status: domain.CloudProviderStatusNotValidated, Details: "role cannot be assumed"},
	}
	l := newTestLifecycle(targetVCP, platform, &fakeCleaner{})
	l.validationTimeout = 20 * time.Millisecond
	l.now = time.Now

	st, err := runSetup(t, l)
	if err == nil || !strings.Contains(err.Error(), "was not validated within") || !strings.Contains(err.Error(), "role cannot be assumed") {
		t.Fatalf("expected a validation error with the details, got %v", err)
	}
	// what was created is recorded, so that teardown removes it
	if len(st.Providers) != 2 {
		t.Fatalf("expected the created providers in the state, got %+v", st.Providers)
	}
}

func TestChecksPassAndLeaveNamesUnchanged(t *testing.T) {
	platform := newFakePlatform()
	l := newTestLifecycle(targetVCP, platform, &fakeCleaner{})
	st, err := runSetup(t, l)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}

	if err := l.runChecks(st); err != nil {
		t.Fatalf("checks failed: %s", err)
	}
	for _, p := range st.Providers {
		if platform.providers[p.ID].Name != p.Name {
			t.Fatalf("provider name changed to %q", platform.providers[p.ID].Name)
		}
	}
	for _, k := range st.Keystores {
		if platform.keystores[k.ID].Name != k.Name {
			t.Fatalf("keystore name changed to %q", platform.keystores[k.ID].Name)
		}
	}
}

func TestChecksDetectALostDiscoverySetting(t *testing.T) {
	platform := newFakePlatform()
	l := newTestLifecycle(targetNGTS, platform, &fakeCleaner{})
	st, err := runSetup(t, l)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}
	// a platform whose update resets the discovery settings, as the real one
	// does when they are not all sent
	l.manager = &resettingPlatform{platform}

	if err := l.runChecks(st); err == nil {
		t.Fatalf("expected the checks to fail")
	}
}

type resettingPlatform struct {
	*fakePlatform
}

func (p *resettingPlatform) UpdateCloudKeystore(r domain.UpdateCloudKeystoreRequest) (*domain.CloudKeystore, error) {
	if k, ok := p.keystores[r.ID]; ok {
		k.DiscoveryConfiguration = &domain.CloudDiscoveryConfiguration{}
	}
	return p.fakePlatform.UpdateCloudKeystore(r)
}

func TestTeardownRemovesEverything(t *testing.T) {
	platform := newFakePlatform()
	cleaner := &fakeCleaner{}
	l := newTestLifecycle(targetVCP, platform, cleaner)
	st, err := runSetup(t, l)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}
	// certificates provisioned by the tests
	aws := domain.NewCertificateCloudMetadata(map[string]interface{}{"arn": "arn:aws:acm:us-east-2:123456789012:certificate/9"})
	azure := domain.NewCertificateCloudMetadata(map[string]interface{}{"name": "cert-1"})
	platform.identities[st.Env["AWS_KEYSTORE_ID"]] = []domain.CloudMachineIdentity{{Status: domain.MachineIdentityStatusInstalled, Metadata: &aws}}
	platform.identities[st.Env["AZURE_KEYSTORE_ID"]] = []domain.CloudMachineIdentity{{Status: domain.MachineIdentityStatusInstalled, Metadata: &azure}}

	if err := l.teardown(st); err != nil {
		t.Fatalf("teardown failed: %s", err)
	}
	if len(platform.providers) != 0 || len(platform.keystores) != 0 {
		t.Fatalf("expected everything to be deleted, left %d providers and %d keystores", len(platform.providers), len(platform.keystores))
	}
	if len(cleaner.deletedARNs) != 1 || len(cleaner.deletedAzure) != 1 || cleaner.deletedAzure[0] != "vcert-auto-do-not-delete/cert-1" {
		t.Fatalf("unexpected certificate deletions: %v %v", cleaner.deletedARNs, cleaner.deletedAzure)
	}
}

func TestTeardownReportsWhatItCouldNotRemove(t *testing.T) {
	platform := newFakePlatform()
	cleaner := &fakeCleaner{}
	l := newTestLifecycle(targetVCP, platform, cleaner)
	st, err := runSetup(t, l)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}
	aws := domain.NewCertificateCloudMetadata(map[string]interface{}{"arn": "arn:aws:acm:us-east-2:123456789012:certificate/9"})
	platform.identities[st.Env["AWS_KEYSTORE_ID"]] = []domain.CloudMachineIdentity{{Status: domain.MachineIdentityStatusInstalled, Metadata: &aws}}
	cleaner.err = errors.New("AccessDeniedException")
	// someone added a keystore to the CI's Azure provider by hand
	platform.addKeystore(domain.CloudKeystore{Name: "manual", CloudProviderID: st.Providers[1].ID,
		AKV: &domain.CloudKeystoreAKVConfiguration{KeyVaultName: "other"}})

	err = l.teardown(st)
	if err == nil || !strings.Contains(err.Error(), "AccessDeniedException") || !strings.Contains(err.Error(), `"manual"`) {
		t.Fatalf("expected both problems to be reported, got %v", err)
	}
	// the keystore whose certificates could not be deleted is kept, so that
	// they can still be found
	if _, ok := platform.keystores[st.Env["AWS_KEYSTORE_ID"]]; !ok {
		t.Fatalf("expected the keystore to be kept")
	}
}

func TestTeardownDeletesCertificatesOnlyFromKeystoresThatCanProvision(t *testing.T) {
	platform := newFakePlatform()
	cleaner := &fakeCleaner{}
	l := newTestLifecycle(targetVCP, platform, cleaner)
	st, err := runSetup(t, l)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}
	var readOnly string
	for _, k := range st.Keystores {
		if k.Location == "vaas-auto-do-not-delete" {
			readOnly = k.ID
		}
	}
	installed := domain.NewCertificateCloudMetadata(map[string]interface{}{"name": "cert-1"})
	platform.identities[readOnly] = []domain.CloudMachineIdentity{{Status: domain.MachineIdentityStatusInstalled, Metadata: &installed}}

	if err := l.teardown(st); err != nil {
		t.Fatalf("teardown failed: %s", err)
	}
	if len(cleaner.deletedAzure) != 0 {
		t.Fatalf("deleted certificates from a keystore that cannot provision: %v", cleaner.deletedAzure)
	}
	if len(platform.keystores) != 0 {
		t.Fatalf("expected the keystores to be deleted")
	}
}

func TestTeardownDeletesACMCertificatesOnlyInTheKeystoreRegionAndAccount(t *testing.T) {
	platform := newFakePlatform()
	cleaner := &fakeCleaner{}
	l := newTestLifecycle(targetVCP, platform, cleaner)
	st, err := runSetup(t, l)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}
	var identities []domain.CloudMachineIdentity
	for _, arn := range []string{
		"arn:aws:acm:us-west-1:123456789012:certificate/other-region",
		"arn:aws:acm:us-east-2:999999999999:certificate/other-account",
		"arn:aws:iam::123456789012:role/not-a-certificate",
	} {
		m := domain.NewCertificateCloudMetadata(map[string]interface{}{"arn": arn})
		identities = append(identities, domain.CloudMachineIdentity{Status: domain.MachineIdentityStatusInstalled, Metadata: &m})
	}
	platform.identities[st.Env["AWS_KEYSTORE_ID"]] = identities

	err = l.teardown(st)
	if err == nil || !strings.Contains(err.Error(), "other-region") || !strings.Contains(err.Error(), "other-account") ||
		!strings.Contains(err.Error(), "not an ACM certificate ARN") {
		t.Fatalf("expected all three certificates to be refused, got %v", err)
	}
	if len(cleaner.deletedARNs) != 0 {
		t.Fatalf("unexpected certificate deletions: %v", cleaner.deletedARNs)
	}
	// kept, so that the certificates can still be found
	if _, ok := platform.keystores[st.Env["AWS_KEYSTORE_ID"]]; !ok {
		t.Fatalf("expected the keystore to be kept")
	}
}

func TestTeardownChecksTheProvidersInTheStateFile(t *testing.T) {
	platform := newFakePlatform()
	l := newTestLifecycle(targetVCP, platform, &fakeCleaner{})
	st, err := runSetup(t, l)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}
	aws, azure := st.Providers[0], st.Providers[1]
	// the AWS provider was deleted by hand; the Azure provider ID now names
	// something the CI did not create
	for _, k := range st.Keystores {
		if k.ProviderID == aws.ID {
			delete(platform.keystores, k.ID)
		}
	}
	delete(platform.providers, aws.ID)
	platform.providers[azure.ID].Name = "Production Azure"

	err = l.teardown(st)
	if err == nil || !strings.Contains(err.Error(), `"Production Azure"`) {
		t.Fatalf("expected a refusal naming the provider, got %v", err)
	}
	if strings.Contains(err.Error(), aws.Name) {
		t.Fatalf("a provider that is already gone should not be an error: %v", err)
	}
	if _, ok := platform.providers[azure.ID]; !ok {
		t.Fatalf("deleted a provider the CI did not create")
	}
}

func TestChecksRestoreNamesWhenRenamingFails(t *testing.T) {
	platform := newFakePlatform()
	l := newTestLifecycle(targetVCP, platform, &fakeCleaner{})
	st, err := runSetup(t, l)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}
	// renaming succeeds, but the platform reports the provider as no longer
	// validated afterwards
	l.manager = &unvalidatingPlatform{platform}

	if err := l.runChecks(st); err == nil {
		t.Fatalf("expected the checks to fail")
	}
	for _, p := range st.Providers {
		if platform.providers[p.ID].Name != p.Name {
			t.Fatalf("provider name left as %q", platform.providers[p.ID].Name)
		}
	}
}

type unvalidatingPlatform struct {
	*fakePlatform
}

func (p *unvalidatingPlatform) UpdateCloudProvider(r domain.UpdateCloudProviderRequest) (*domain.CloudProvider, error) {
	cp, err := p.fakePlatform.UpdateCloudProvider(r)
	if err == nil {
		cp.Status = domain.CloudProviderStatusNotValidated
	}
	return cp, err
}

func TestRemovingStaleKeystoreWarnsAboutCertificatesLeftInTheCloud(t *testing.T) {
	platform := newFakePlatform()
	cleaner := &fakeCleaner{}
	// a crashed run's keystore in a region that is no longer configured
	old := platform.addProvider(domain.CloudProvider{
		Name: ciName(testNow.Add(-5*time.Hour), "40", "aws1"), Type: domain.CloudProviderTypeAWS,
		Status: domain.CloudProviderStatusValidated,
		AWS:    &domain.CloudProviderAWSConfiguration{AccountID: "123456789012"},
	})
	ks := platform.addKeystore(domain.CloudKeystore{
		Name: ciName(testNow.Add(-5*time.Hour), "40", "aws1-ks9"), CloudProviderID: old.ID,
		ACM: &domain.CloudKeystoreACMConfiguration{Region: "eu-west-3"},
	})
	installed := domain.NewCertificateCloudMetadata(map[string]interface{}{"arn": "arn:aws:acm:eu-west-3:123456789012:certificate/7"})
	platform.identities[ks.ID] = []domain.CloudMachineIdentity{{ID: "m1", Status: domain.MachineIdentityStatusInstalled, Metadata: &installed}}
	l := newTestLifecycle(targetVCP, platform, cleaner)
	var log strings.Builder
	logOutput = &log
	t.Cleanup(func() { logOutput = io.Discard })

	if _, err := runSetup(t, l); err != nil {
		t.Fatalf("setup failed: %s", err)
	}
	if len(cleaner.deletedARNs) != 0 {
		t.Fatalf("deleted a certificate from a keystore that cannot provision: %v", cleaner.deletedARNs)
	}
	if !strings.Contains(log.String(), "WARNING: not deleting certificate arn:aws:acm:eu-west-3:123456789012:certificate/7") {
		t.Fatalf("expected a warning about the certificate left in the cloud, got:\n%s", log.String())
	}
}

func TestTeardownRetriesListingProviders(t *testing.T) {
	platform := newFakePlatform()
	l := newTestLifecycle(targetVCP, platform, &fakeCleaner{})
	st, err := runSetup(t, l)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}
	flaky := &flakyListPlatform{fakePlatform: platform, failures: 2}
	l.manager = flaky

	if err := l.teardown(st); err != nil {
		t.Fatalf("teardown failed: %s", err)
	}
	if len(platform.providers) != 0 {
		t.Fatalf("expected everything to be deleted, left %d providers", len(platform.providers))
	}

	// a platform that keeps failing is reported
	flaky.failures = 10
	if err := l.teardown(st); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("expected the listing error, got %v", err)
	}
}

// flakyListPlatform fails the first listings of cloud providers
type flakyListPlatform struct {
	*fakePlatform
	failures int
}

func (p *flakyListPlatform) ListCloudProviders(filter domain.GetCloudProviderRequest) ([]domain.CloudProvider, error) {
	if p.failures > 0 {
		p.failures--
		return nil, errors.New("service unavailable")
	}
	return p.fakePlatform.ListCloudProviders(filter)
}

func TestTeardownRemovesKeystoresThatCannotProvisionWhenListingFails(t *testing.T) {
	platform := newFakePlatform()
	l := newTestLifecycle(targetVCP, platform, &fakeCleaner{})
	st, err := runSetup(t, l)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}
	failing := map[string]bool{}
	for _, k := range st.Keystores {
		if !k.CanProvision {
			failing[k.ID] = true
		}
	}
	l.manager = &failingIdentitiesPlatform{fakePlatform: platform, failing: failing}

	if err := l.teardown(st); err != nil {
		t.Fatalf("teardown failed: %s", err)
	}
	if len(platform.providers) != 0 || len(platform.keystores) != 0 {
		t.Fatalf("expected everything to be deleted, left %d providers and %d keystores", len(platform.providers), len(platform.keystores))
	}
}

// failingIdentitiesPlatform fails listing the machine identities of some keystores
type failingIdentitiesPlatform struct {
	*fakePlatform
	failing map[string]bool
}

func (p *failingIdentitiesPlatform) ListMachineIdentities(r domain.ListCloudMachineIdentitiesRequest) ([]domain.CloudMachineIdentity, error) {
	if p.failing[r.KeystoreID] {
		return nil, errors.New("cannot convert metadata")
	}
	return p.fakePlatform.ListMachineIdentities(r)
}

func TestTeardownDoesNothingWhenSkipped(t *testing.T) {
	l := newTestLifecycle(targetVCP, newFakePlatform(), &fakeCleaner{})
	if err := l.teardown(&state{Skipped: true}); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if err := l.teardown(nil); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestCINames(t *testing.T) {
	name := ciName(testNow, "4725", "aws1-ks1")
	if name != fmt.Sprintf("vcert-ci-%d-4725-aws1-ks1", testNow.Unix()) {
		t.Fatalf("unexpected name %q", name)
	}
	created, ok := ciCreated(name)
	if !ok || !created.Equal(testNow) {
		t.Fatalf("unexpected creation time %v, %t", created, ok)
	}
	for _, other := range []string{"Production AWS", "vcert-ci-", "vcert-ci-abc-1-aws1", "my-vcert-ci-1-1-aws1"} {
		if _, ok := ciCreated(other); ok {
			t.Fatalf("%q should not be recognized as a CI name", other)
		}
	}
}
