/*
 * Copyright 2022 Venafi, Inc.
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

package cloud_convert

import (
	"path/filepath"
	"testing"

	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/Venafi/vcert/v4/test"
)

func TestBuildCloudCitRequest(t *testing.T) {
	absPath, err := filepath.Abs("../../../../../test-files/policy_specification_cloud.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification, err := policy.GetPolicySpecificationFromFile(absPath, true)
	if err != nil {
		t.Fatalf("Error loading specification \nError: %s", err)
	}

	prodId := "testiong"
	var orgId int64
	orgId = 1234
	cd := policy.CADetails{
		CertificateAuthorityProductOptionId: &prodId,
		CertificateAuthorityOrganizationId:  &orgId,
	}

	_, err = BuildCloudCitRequest(policySpecification, &cd)

	if err != nil {
		t.Fatalf("Error building cit \nError: %s", err)
	}
}

func TestBuildCloudCitRequestWithEmptyPS(t *testing.T) {
	absPath, err := filepath.Abs("../../../../../test-files/empty_policy.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification, err := policy.GetPolicySpecificationFromFile(absPath, true)
	if err != nil {
		t.Fatalf("Error loading specification \nError: %s", err)
	}

	prodId := "testiong"
	var orgId int64
	orgId = 1234
	cd := policy.CADetails{
		CertificateAuthorityProductOptionId: &prodId,
		CertificateAuthorityOrganizationId:  &orgId,
	}

	_, err = BuildCloudCitRequest(policySpecification, &cd)

	if err != nil {
		t.Fatalf("Error building cit \nError: %s", err)
	}
}

func TestGetPolicy(t *testing.T) {

	t.Skip() //this is just for development purpose

	/*
		policyName := os.Getenv("CLOUD_POLICY_MANAGEMENT_SAMPLE")
		conn := getTestConnector(ctx.CloudZone)
		conn.verbose = true

		err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})

		if err != nil {
			t.Fatalf("%s", err)
		}

		specifiedPS := test.GetCloudPolicySpecification()

		ps, err := conn.GetPolicy(policyName)

		if err != nil {
			t.Fatalf("%s", err)
		}
	*/
	t.Fatalf("test needs fixing")
	var ps *policy.PolicySpecification
	var specifiedPS *policy.PolicySpecification

	//validate each attribute
	//validate subject attributes

	if ps == nil {
		t.Fatalf("specified Policy wasn't found")
	}

	if ps.Policy.Domains != nil && specifiedPS.Policy.Domains != nil {
		domains := convertToRegex(specifiedPS.Policy.Domains, isWildcardAllowed(*(specifiedPS)))
		valid := test.IsArrayStringEqual(domains, ps.Policy.Domains)
		if !valid {
			t.Fatalf("specified domains are different")
		}
	}

	if *(ps.Policy.MaxValidDays) != *(specifiedPS.Policy.MaxValidDays) {
		t.Fatalf("specified validity period is different")
	}

	//validate cert authority
	if ps.Policy.CertificateAuthority == nil || *(ps.Policy.CertificateAuthority) == "" {
		t.Fatalf("venafi policy doesn't have a certificate authority")
	}
	if *(ps.Policy.CertificateAuthority) != *(specifiedPS.Policy.CertificateAuthority) {
		t.Fatalf("certificate authority value doesn't match, get: %s but expected: %s", *(ps.Policy.CertificateAuthority), *(specifiedPS.Policy.CertificateAuthority))
	}

	if specifiedPS.Policy.Subject.Orgs != nil {

		if ps.Policy.Subject.Orgs == nil {
			t.Fatalf("specified policy orgs are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.Subject.Orgs, ps.Policy.Subject.Orgs)
		if !valid {
			t.Fatalf("specified policy orgs are different")
		}

	}

	if specifiedPS.Policy.Subject.OrgUnits != nil {

		if ps.Policy.Subject.OrgUnits == nil {
			t.Fatalf("specified policy orgs units are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.Subject.OrgUnits, ps.Policy.Subject.OrgUnits)
		if !valid {
			t.Fatalf("specified policy orgs units are different")
		}

	}

	if specifiedPS.Policy.Subject.Localities != nil {

		if ps.Policy.Subject.Localities == nil {
			t.Fatalf("specified policy localities are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.Subject.Localities, ps.Policy.Subject.Localities)
		if !valid {
			t.Fatalf("specified policy localities are different")
		}

	}

	if specifiedPS.Policy.Subject.States != nil {

		if ps.Policy.Subject.States == nil {
			t.Fatalf("specified policy states are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.Subject.States, ps.Policy.Subject.States)
		if !valid {
			t.Fatalf("specified policy states are different")
		}

	}

	if specifiedPS.Policy.Subject.Countries != nil {

		if ps.Policy.Subject.Countries == nil {
			t.Fatalf("specified policy countries are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.Subject.Countries, ps.Policy.Subject.Countries)
		if !valid {
			t.Fatalf("specified policy countries are different")
		}

	}

	//validate key pair values.

	if specifiedPS.Policy.KeyPair.KeyTypes != nil {

		if ps.Policy.KeyPair.KeyTypes == nil {
			t.Fatalf("specified policy key types are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.KeyPair.KeyTypes, ps.Policy.KeyPair.KeyTypes)
		if !valid {
			t.Fatalf("specified policy key types are different")
		}

	}

	if specifiedPS.Policy.KeyPair.RsaKeySizes != nil {

		if ps.Policy.KeyPair.RsaKeySizes == nil {
			t.Fatalf("specified policy rsa key sizes are not specified")
		}

		valid := test.IsArrayIntEqual(specifiedPS.Policy.KeyPair.RsaKeySizes, ps.Policy.KeyPair.RsaKeySizes)
		if !valid {
			t.Fatalf("specified policy rsa key sizes are different")
		}

	}

	if specifiedPS.Policy.KeyPair.ReuseAllowed != nil {

		if ps.Policy.KeyPair.ReuseAllowed == nil {
			t.Fatalf("specified policy rsa key sizes are not specified")
		}

		if *(ps.Policy.KeyPair.ReuseAllowed) != *(specifiedPS.Policy.KeyPair.ReuseAllowed) {
			t.Fatalf("specified policy rsa key sizes are different")
		}

	}

	//validate default values.
	if specifiedPS.Default.Subject.Org != nil {
		if ps.Default.Subject.Org == nil {
			t.Fatalf("specified policy default org is not specified")
		}
		if *(ps.Default.Subject.Org) != *(specifiedPS.Default.Subject.Org) {
			t.Fatalf("specified policy default org is different")
		}
	}

	if specifiedPS.Default.Subject.OrgUnits != nil {

		if ps.Default.Subject.OrgUnits == nil {
			t.Fatalf("specified policy default org is not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Default.Subject.OrgUnits, ps.Default.Subject.OrgUnits)

		if !valid {
			t.Fatalf("specified policy default org unit are different")
		}

	}

	if specifiedPS.Default.Subject.Locality != nil {
		if ps.Default.Subject.Locality == nil {
			t.Fatalf("specified policy default locality is not specified")
		}
		if *(ps.Default.Subject.Locality) != *(specifiedPS.Default.Subject.Locality) {
			t.Fatalf("specified policy default locality is different")
		}
	}

	if specifiedPS.Default.Subject.State != nil {
		if ps.Default.Subject.State == nil {
			t.Fatalf("specified policy default state is not specified")
		}
		if *(ps.Default.Subject.State) != *(specifiedPS.Default.Subject.State) {
			t.Fatalf("specified policy default state is different")
		}
	}

	if specifiedPS.Default.Subject.Country != nil {
		if ps.Default.Subject.Country == nil {
			t.Fatalf("policy default country is not specified")
		}
		if *(ps.Default.Subject.Country) != *(specifiedPS.Default.Subject.Country) {
			t.Fatalf("specified policy default country is different")
		}
	}

	if specifiedPS.Default.KeyPair.KeyType != nil {
		if ps.Default.KeyPair.KeyType == nil {
			t.Fatalf("policy default key type is not specified ")
		}
		if *(ps.Default.KeyPair.KeyType) != *(specifiedPS.Default.KeyPair.KeyType) {
			t.Fatalf("specified policy default key type is different")
		}
	}

	if specifiedPS.Default.KeyPair.RsaKeySize != nil {
		if ps.Default.KeyPair.RsaKeySize == nil {
			t.Fatalf("policy default rsa key size is not specified")
		}
		if *(ps.Default.KeyPair.RsaKeySize) != *(specifiedPS.Default.KeyPair.RsaKeySize) {
			t.Fatalf("specified policy default rsa key size is different")
		}
	}

}
