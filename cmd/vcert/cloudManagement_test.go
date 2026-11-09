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
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/venafi"
)

func TestCloudManagementRejectsOtherPlatforms(t *testing.T) {
	for _, platform := range []venafi.Platform{venafi.TPP, venafi.TLSPCloud, venafi.Firefly} {
		flags = commandFlags{platform: platform, token: "a-token"}
		t.Setenv(vCertPlatform, "")

		err := validateCloudManagementConnectionFlags("cloudprovider list")
		if err == nil {
			t.Fatalf("expected an error for platform %s", platform)
		}
		expected := "command cloudprovider list not supported for " + platform.String()
		if err.Error() != expected {
			t.Fatalf("expected %q, got %q", expected, err.Error())
		}
	}
}

func TestCloudManagementRequiresPlatform(t *testing.T) {
	flags = commandFlags{token: "a-token"}
	t.Setenv(vCertPlatform, "")

	err := validateCloudManagementConnectionFlags("cloudkeystore get")
	if err == nil || !strings.Contains(err.Error(), "only supported for NGTS") {
		t.Fatalf("expected a platform required error, got %v", err)
	}
}

func TestCloudManagementPlatformFromEnvironment(t *testing.T) {
	flags = commandFlags{token: "a-token"}
	t.Setenv(vCertPlatform, "tpp")

	err := validateCloudManagementConnectionFlags("cloudkeystore get")
	if err == nil || err.Error() != "command cloudkeystore get not supported for TPP" {
		t.Fatalf("expected TPP to be rejected, got %v", err)
	}
}

func TestCloudManagementAcceptsNGTS(t *testing.T) {
	flags = commandFlags{platform: venafi.NGTS, token: "a-token"}
	t.Setenv(vCertPlatform, "")

	if err := validateCloudManagementConnectionFlags("cloudprovider list"); err != nil {
		t.Fatalf("expected NGTS to be accepted, got %s", err)
	}
}

func TestRunBeforeCloudManagementCommandReadsPlatformFromEnvironment(t *testing.T) {
	flags = commandFlags{}
	t.Setenv(vCertPlatform, "ngts")

	if err := runBeforeCloudManagementCommand(newTestCliContext(t)); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if flags.platform != venafi.NGTS {
		t.Fatalf("expected the platform to be read from %s, got %s", vCertPlatform, flags.platform)
	}
}

func TestCloudProviderCreateRequiresTypeSpecificFlags(t *testing.T) {
	t.Setenv(vCertPlatform, "")
	t.Setenv(vcertAzureSecret, "")

	tests := []struct {
		name     string
		flags    commandFlags
		expected string
	}{
		{"aws", commandFlags{cloudType: "aws", awsRole: "role"}, "--aws-account-id"},
		{"azure without secret", commandFlags{cloudType: "azure", azureApplicationID: "app", azureDirectoryID: "dir"}, "--azure-secret"},
		{"gcp", commandFlags{cloudType: "gcp"}, "--gcp-service-account-email"},
		{"gcp bad method", commandFlags{cloudType: "gcp", gcpServiceAccountEmail: "sa", gcpAuthorizationMethod: "password"}, "unexpected GCP authorization method"},
		{"unknown type", commandFlags{cloudType: "oci"}, "unexpected cloud provider type"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flags = tc.flags
			flags.platform = venafi.NGTS
			flags.token = "a-token"
			flags.providerName = "provider"

			err := validateCloudProviderCreateFlags("cloudprovider create")
			if err == nil || !strings.Contains(err.Error(), tc.expected) {
				t.Fatalf("expected an error containing %q, got %v", tc.expected, err)
			}
		})
	}
}

func TestCloudProviderCreateAcceptsAzureSecretFromEnvironment(t *testing.T) {
	t.Setenv(vCertPlatform, "")
	t.Setenv(vcertAzureSecret, "secret")
	flags = commandFlags{platform: venafi.NGTS, token: "a-token", providerName: "provider", cloudType: "azure", azureApplicationID: "app", azureDirectoryID: "dir"}

	if err := validateCloudProviderCreateFlags("cloudprovider create"); err != nil {
		t.Fatalf("expected the secret from the environment to be accepted, got %s", err)
	}
}

func newTestCliContext(t *testing.T, set ...string) *cli.Context {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String(flagAzureSecret.Name, "", "")
	for _, name := range set {
		if err := fs.Set(name, "value"); err != nil {
			t.Fatal(err)
		}
	}
	return cli.NewContext(cli.NewApp(), fs, nil)
}

func TestBuildUpdateCloudProviderRequestRejectsOptionsOfAnotherType(t *testing.T) {
	flags = commandFlags{awsRole: "role"}
	provider := domain.CloudProvider{ID: "p1", Name: "gcp", Type: domain.CloudProviderTypeGCP}

	_, err := buildUpdateCloudProviderRequest(newTestCliContext(t), provider)
	if err == nil || !strings.Contains(err.Error(), "AWS options cannot be set") {
		t.Fatalf("expected a type mismatch error, got %v", err)
	}
}

func TestBuildUpdateCloudProviderRequestIgnoresAzureSecretFromEnvironment(t *testing.T) {
	// buildConfig copies VCERT_AZURE_SECRET into the flags, which must not turn
	// an update of a non-Azure provider into an Azure configuration change
	flags = commandFlags{newName: "renamed", azureSecret: "from-env"}
	provider := domain.CloudProvider{ID: "p1", Name: "aws", Type: domain.CloudProviderTypeAWS}

	request, err := buildUpdateCloudProviderRequest(newTestCliContext(t), provider)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if request.Azure != nil || request.Name == nil || *request.Name != "renamed" {
		t.Fatalf("unexpected request: %+v", request)
	}
}

func TestBuildUpdateCloudProviderRequestRequiresAChange(t *testing.T) {
	flags = commandFlags{}
	provider := domain.CloudProvider{ID: "p1", Name: "aws", Type: domain.CloudProviderTypeAWS}

	_, err := buildUpdateCloudProviderRequest(newTestCliContext(t), provider)
	if err == nil || !strings.Contains(err.Error(), "nothing to update") {
		t.Fatalf("expected a nothing to update error, got %v", err)
	}
}

// fakeCloudManager implements endpoint.CloudProviderManager and
// endpoint.CloudKeystoreManager for tests
type fakeCloudManager struct {
	providers []domain.CloudProvider
	// keystoreResponses are returned by successive ListCloudKeystores calls;
	// the last one is repeated
	keystoreResponses [][]domain.CloudKeystore
	keystoreCalls     int
}

func (f *fakeCloudManager) ListCloudProviders(filter domain.GetCloudProviderRequest) ([]domain.CloudProvider, error) {
	result := make([]domain.CloudProvider, 0)
	for _, p := range f.providers {
		// like the API, the name filter matches partial names
		if strings.Contains(p.Name, filter.Name) {
			result = append(result, p)
		}
	}
	return result, nil
}

func (f *fakeCloudManager) CreateCloudProvider(domain.CreateCloudProviderRequest) (*domain.CloudProvider, error) {
	return nil, nil
}

func (f *fakeCloudManager) UpdateCloudProvider(domain.UpdateCloudProviderRequest) (*domain.CloudProvider, error) {
	return nil, nil
}

func (f *fakeCloudManager) DeleteCloudProvider(string) error { return nil }

func (f *fakeCloudManager) ValidateCloudProvider(string) (*domain.CloudProviderValidationResult, error) {
	return nil, nil
}

func (f *fakeCloudManager) ListCloudKeystores(domain.GetCloudKeystoreRequest) ([]domain.CloudKeystore, error) {
	i := f.keystoreCalls
	if i >= len(f.keystoreResponses) {
		i = len(f.keystoreResponses) - 1
	}
	f.keystoreCalls++
	return f.keystoreResponses[i], nil
}

func (f *fakeCloudManager) CreateCloudKeystore(domain.CreateCloudKeystoreRequest) (*domain.CloudKeystore, error) {
	return nil, nil
}

func (f *fakeCloudManager) UpdateCloudKeystore(domain.UpdateCloudKeystoreRequest) (*domain.CloudKeystore, error) {
	return nil, nil
}

func (f *fakeCloudManager) DeleteCloudKeystore(string) error { return nil }

func (f *fakeCloudManager) StartCloudDiscovery(string) (*domain.WorkflowResult, error) {
	return nil, nil
}

func (f *fakeCloudManager) AbortCloudDiscovery(string) error { return nil }

func (f *fakeCloudManager) ListMachineIdentities(domain.ListCloudMachineIdentitiesRequest) ([]domain.CloudMachineIdentity, error) {
	return nil, nil
}

func TestResolveCloudProviderMatchesExactName(t *testing.T) {
	manager := &fakeCloudManager{providers: []domain.CloudProvider{
		{ID: "p1", Name: "aws"},
		{ID: "p2", Name: "aws-staging"},
	}}

	provider, err := resolveCloudProvider(manager, "", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if provider.ID != "p1" {
		t.Fatalf("expected provider p1, got %s", provider.ID)
	}
}

func TestResolveCloudProviderByID(t *testing.T) {
	manager := &fakeCloudManager{providers: []domain.CloudProvider{{ID: "p1", Name: "aws"}, {ID: "p2", Name: "gcp"}}}

	provider, err := resolveCloudProvider(manager, "p2", "")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if provider.Name != "gcp" {
		t.Fatalf("expected provider gcp, got %s", provider.Name)
	}

	if _, err := resolveCloudProvider(manager, "p3", ""); err == nil {
		t.Fatalf("expected an error for an unknown provider ID")
	}
}

func TestResolveCloudKeystoreRejectsAmbiguousName(t *testing.T) {
	flags = commandFlags{keystoreName: "us-east-1"}
	manager := &fakeCloudManager{keystoreResponses: [][]domain.CloudKeystore{{{ID: "k1"}, {ID: "k2"}}}}

	_, err := resolveCloudKeystore(manager)
	if err == nil || !strings.Contains(err.Error(), "found 2 cloud keystores") {
		t.Fatalf("expected an ambiguity error, got %v", err)
	}
}

func TestIsNewDiscovery(t *testing.T) {
	earlier := time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)
	later := earlier.Add(24 * time.Hour)

	tests := []struct {
		name     string
		previous *domain.CloudDiscovery
		current  domain.CloudDiscovery
		expected bool
	}{
		{"no previous discovery", nil, domain.CloudDiscovery{ID: "d1"}, true},
		{"never initiated before", &domain.CloudDiscovery{ID: "d1", Status: domain.CloudDiscoveryStatusNeverInitiated}, domain.CloudDiscovery{ID: "d1"}, true},
		{"different ID", &domain.CloudDiscovery{ID: "d1", StartTime: &earlier}, domain.CloudDiscovery{ID: "d2", StartTime: &earlier}, true},
		{"same ID started later", &domain.CloudDiscovery{ID: "d1", StartTime: &earlier}, domain.CloudDiscovery{ID: "d1", StartTime: &later}, true},
		{"same run", &domain.CloudDiscovery{ID: "d1", StartTime: &earlier}, domain.CloudDiscovery{ID: "d1", StartTime: &earlier}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNewDiscovery(tc.previous, &tc.current); got != tc.expected {
				t.Fatalf("expected %t, got %t", tc.expected, got)
			}
		})
	}
}

func TestWaitForCloudDiscoverySkipsThePreviousRun(t *testing.T) {
	defer func(interval time.Duration) { discoveryPollInterval = interval }(discoveryPollInterval)
	discoveryPollInterval = time.Millisecond

	earlier := time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)
	later := earlier.Add(24 * time.Hour)
	previous := &domain.CloudDiscovery{ID: "d1", Status: domain.CloudDiscoveryStatusCompleted, StartTime: &earlier}

	manager := &fakeCloudManager{keystoreResponses: [][]domain.CloudKeystore{
		// the API has not picked up the new discovery yet
		{{ID: "k1", Discovery: previous}},
		{{ID: "k1", Discovery: &domain.CloudDiscovery{ID: "d1", Status: domain.CloudDiscoveryStatusRunning, StartTime: &later}}},
		{{ID: "k1", Discovery: &domain.CloudDiscovery{ID: "d1", Status: domain.CloudDiscoveryStatusCompleted, StartTime: &later, NewCertificatesCount: 4}}},
	}}

	keystore, err := waitForCloudDiscovery(manager, "k1", previous, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if keystore.Discovery.NewCertificatesCount != 4 {
		t.Fatalf("expected the new discovery's results, got %+v", keystore.Discovery)
	}
	if manager.keystoreCalls != 3 {
		t.Fatalf("expected 3 polls, got %d", manager.keystoreCalls)
	}
}

func TestWaitForCloudDiscoveryTimesOut(t *testing.T) {
	defer func(interval time.Duration) { discoveryPollInterval = interval }(discoveryPollInterval)
	discoveryPollInterval = time.Millisecond

	manager := &fakeCloudManager{keystoreResponses: [][]domain.CloudKeystore{
		{{ID: "k1", Discovery: &domain.CloudDiscovery{ID: "d1", Status: domain.CloudDiscoveryStatusRunning}}},
	}}

	_, err := waitForCloudDiscovery(manager, "k1", nil, 20*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected a timeout error, got %v", err)
	}
}

func TestCloudProviderOutputIncludesConfiguration(t *testing.T) {
	out := newCloudProviderOutput(domain.CloudProvider{
		ID: "p1", Name: "gcp", Type: domain.CloudProviderTypeGCP, Status: domain.CloudProviderStatusNotValidated,
		GCP: &domain.CloudProviderGCPConfiguration{
			ServiceAccountEmail: "sa@p.iam.gserviceaccount.com",
			AuthorizationMethod: domain.GCPAuthorizationMethodVenafiGeneratedKey,
			PublicKey:           "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
		},
	}).text()

	for _, expected := range []string{
		"gcpServiceAccountEmail: sa@p.iam.gserviceaccount.com\n",
		"gcpAuthorizationMethod: VENAFI_GENERATED_KEY\n",
		"gcpPublicKey: |\n  -----BEGIN PUBLIC KEY-----\n  AAAA\n  -----END PUBLIC KEY-----\n",
	} {
		if !strings.Contains(out, expected) {
			t.Fatalf("expected the output to contain %q, got:\n%s", expected, out)
		}
	}
}
