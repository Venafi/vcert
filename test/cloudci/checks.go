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
	"fmt"

	"github.com/Venafi/vcert/v5/pkg/domain"
)

// The CRUD checks run between setup and teardown, on the objects setup
// created. They leave the names as they found them, because the provisioning
// tests find the keystores by name.

type checkResults struct {
	passed int
	failed []string
}

func (r *checkResults) check(name string, err error) {
	if err != nil {
		r.failed = append(r.failed, name+": "+err.Error())
		logf("FAIL %s: %s", name, err)
		return
	}
	r.passed++
	logf("PASS %s", name)
}

func (r *checkResults) err() error {
	if len(r.failed) == 0 {
		return nil
	}
	return fmt.Errorf("%d of %d checks failed", len(r.failed), len(r.failed)+r.passed)
}

func (l *lifecycle) runChecks(st *state) error {
	if st == nil || st.Skipped {
		return nil
	}
	var r checkResults
	for _, p := range st.Providers {
		l.checkProvider(&r, p)
	}
	for _, k := range st.Keystores {
		l.checkKeystore(&r, k)
	}
	if len(st.Keystores) > 0 {
		k := st.Keystores[0]
		r.check("delete of a cloud provider with keystores is refused", func() error {
			if err := l.manager.DeleteCloudProvider(k.ProviderID); err == nil {
				return fmt.Errorf("the cloud provider of keystore %q was deleted", k.Name)
			}
			_, err := l.findProvider(k.ProviderID)
			return err
		}())
	}
	logf("%d checks passed, %d failed", r.passed, len(r.failed))
	return r.err()
}

func (l *lifecycle) findProvider(id string) (*domain.CloudProvider, error) {
	providers, err := l.manager.ListCloudProviders(domain.GetCloudProviderRequest{})
	if err != nil {
		return nil, err
	}
	for i := range providers {
		if providers[i].ID == id {
			return &providers[i], nil
		}
	}
	return nil, fmt.Errorf("cloud provider %s not found", id)
}

func (l *lifecycle) findKeystore(id string) (*domain.CloudKeystore, error) {
	keystores, err := l.manager.ListCloudKeystores(domain.GetCloudKeystoreRequest{CloudKeystoreID: &id})
	if err != nil {
		return nil, err
	}
	for i := range keystores {
		if keystores[i].ID == id {
			return &keystores[i], nil
		}
	}
	return nil, fmt.Errorf("cloud keystore %s not found", id)
}

func (l *lifecycle) checkProvider(r *checkResults, p providerState) {
	prefix := "provider " + p.Name + ": "

	r.check(prefix+"read back with its configuration and validated", func() error {
		cp, err := l.findProvider(p.ID)
		if err != nil {
			return err
		}
		if cp.Status != domain.CloudProviderStatusValidated {
			return fmt.Errorf("status is %s", cp.Status)
		}
		switch p.Kind {
		case kindAWS:
			want := l.aws.CloudProviders[p.ConfigIndex]
			if cp.AWS == nil || cp.AWS.AccountID != want.AccountID || cp.AWS.Role != want.IAMRoleName {
				return fmt.Errorf("unexpected AWS configuration %+v", cp.AWS)
			}
			if cp.AWS.ExternalID == "" {
				return fmt.Errorf("no external ID")
			}
		case kindAzure:
			want := l.azure.CloudProviders[p.ConfigIndex]
			if cp.Azure == nil || cp.Azure.ApplicationID != want.ClientID || cp.Azure.DirectoryID != want.TenantID {
				return fmt.Errorf("unexpected Azure configuration %+v", cp.Azure)
			}
		}
		return nil
	}())

	r.check(prefix+"renamed and renamed back, staying validated", func() error {
		renamed := p.Name + "-renamed"
		for _, name := range []string{renamed, p.Name} {
			cp, err := l.manager.UpdateCloudProvider(domain.UpdateCloudProviderRequest{ID: p.ID, Type: l.providerType(p), Name: &name})
			if err != nil {
				return err
			}
			if cp.Name != name {
				return fmt.Errorf("name is %q after renaming to %q", cp.Name, name)
			}
			if cp.Status != domain.CloudProviderStatusValidated {
				return fmt.Errorf("status is %s after renaming", cp.Status)
			}
		}
		return nil
	}())

	r.check(prefix+"found by name", func() error {
		providers, err := l.manager.ListCloudProviders(domain.GetCloudProviderRequest{Name: p.Name})
		if err != nil {
			return err
		}
		if len(providers) != 1 || providers[0].ID != p.ID {
			return fmt.Errorf("found %d cloud providers", len(providers))
		}
		return nil
	}())
}

func (l *lifecycle) providerType(p providerState) domain.CloudProviderType {
	if p.Kind == kindAzure {
		return domain.CloudProviderTypeAzure
	}
	return domain.CloudProviderTypeAWS
}

func (l *lifecycle) checkKeystore(r *checkResults, k keystoreState) {
	prefix := "keystore " + k.Name + ": "

	r.check(prefix+"read back with its configuration", func() error {
		ks, err := l.findKeystore(k.ID)
		if err != nil {
			return err
		}
		if ks.CloudProviderID != k.ProviderID {
			return fmt.Errorf("belongs to cloud provider %s", ks.CloudProviderID)
		}
		switch k.Kind {
		case kindAWS:
			if ks.ACM == nil || ks.ACM.Region != k.Location {
				return fmt.Errorf("unexpected ACM configuration %+v", ks.ACM)
			}
		case kindAzure:
			if ks.AKV == nil || ks.AKV.KeyVaultName != k.Location {
				return fmt.Errorf("unexpected AKV configuration %+v", ks.AKV)
			}
		}
		return nil
	}())

	schedule := "00 03 * * *"
	yes, no := true, false
	r.check(prefix+"discovery settings set", l.updateAndExpect(k, domain.UpdateCloudKeystoreRequest{
		Discovery: &domain.CloudDiscoveryOptions{ScheduleSpecification: &schedule, IncludeExpiredCertificates: &yes, IncludeRevokedCertificates: &no},
	}, k.Name, domain.CloudDiscoveryConfiguration{ScheduleSpecification: schedule, IncludeExpiredCertificates: true}))

	r.check(prefix+"changing one discovery setting keeps the others", l.updateAndExpect(k, domain.UpdateCloudKeystoreRequest{
		Discovery: &domain.CloudDiscoveryOptions{IncludeRevokedCertificates: &yes},
	}, k.Name, domain.CloudDiscoveryConfiguration{ScheduleSpecification: schedule, IncludeExpiredCertificates: true, IncludeRevokedCertificates: true}))

	renamed := k.Name + "-renamed"
	r.check(prefix+"renaming keeps the discovery settings", func() error {
		all := domain.CloudDiscoveryConfiguration{ScheduleSpecification: schedule, IncludeExpiredCertificates: true, IncludeRevokedCertificates: true}
		if err := l.updateAndExpect(k, domain.UpdateCloudKeystoreRequest{Name: &renamed}, renamed, all); err != nil {
			return err
		}
		name := k.Name
		return l.updateAndExpect(k, domain.UpdateCloudKeystoreRequest{Name: &name}, k.Name, all)
	}())

	empty := ""
	r.check(prefix+"clearing the schedule keeps the other settings", l.updateAndExpect(k, domain.UpdateCloudKeystoreRequest{
		Discovery: &domain.CloudDiscoveryOptions{ScheduleSpecification: &empty, IncludeExpiredCertificates: &no, IncludeRevokedCertificates: &no},
	}, k.Name, domain.CloudDiscoveryConfiguration{}))

	r.check(prefix+"machine identities listed", func() error {
		_, err := l.manager.ListMachineIdentities(domain.ListCloudMachineIdentitiesRequest{KeystoreID: k.ID})
		return err
	}())
}

// updateAndExpect updates a keystore, then reads it back and compares its
// name and discovery settings with the expected ones
func (l *lifecycle) updateAndExpect(k keystoreState, request domain.UpdateCloudKeystoreRequest, wantName string, want domain.CloudDiscoveryConfiguration) error {
	request.ID = k.ID
	if _, err := l.manager.UpdateCloudKeystore(request); err != nil {
		return err
	}
	ks, err := l.findKeystore(k.ID)
	if err != nil {
		return err
	}
	if ks.Name != wantName {
		return fmt.Errorf("name is %q, want %q", ks.Name, wantName)
	}
	got := domain.CloudDiscoveryConfiguration{}
	if ks.DiscoveryConfiguration != nil {
		got = *ks.DiscoveryConfiguration
	}
	if got != want {
		return fmt.Errorf("discovery settings are %+v, want %+v", got, want)
	}
	return nil
}
