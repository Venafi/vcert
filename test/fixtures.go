/*
 * Copyright 2018 Venafi, Inc.
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

package test

import (
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/policy"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randRunes(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, n)
	for i := range b {
		/* #nosec */
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func RandCN() string {
	return fmt.Sprintf("t%d-%s.venafi.example.com", time.Now().Unix(), randRunes(4))
}

func RandSpecificCN(cn string) string {
	return fmt.Sprintf("t%d-%s.%s", time.Now().Unix(), randRunes(4), cn)
}

func RandAppName() string {
	return fmt.Sprintf("vcert-go-%d-%sAppOpenSource", time.Now().Unix(), randRunes(4))
}

func RandCitName() string {
	return fmt.Sprintf("t%d-%sCitOpenSource", time.Now().Unix(), randRunes(4))
}

func RandTppPolicyName() string {
	return fmt.Sprintf("vcert-go-%d-%sPolicyOpenSource", time.Now().Unix(), randRunes(4))
}

func GetCloudPolicySpecification() *policy.PolicySpecification {
	caName := os.Getenv("CLOUD_CA_NAME")
	validityHours := 120
	wildcardAllowed := true
	serviceGenerated := true
	reuseAllowed := false
	subjectAltNamesAllowed := true
	upnAllowed := false

	domain := "venafi.com"
	org := "Venafi"
	locality := "Salt Lake City"
	state := "Utah"
	country := "US"

	defaultKeyType := "RSA"
	defaultKeySize := 2048

	specification := policy.PolicySpecification{
		Policy: &policy.Policy{
			CertificateAuthority: &caName,
			Domains:              []string{"venafi.com"},
			WildcardAllowed:      &wildcardAllowed,
			MaxValidDays:         &validityHours,
			Subject: &policy.Subject{
				Orgs:       []string{"Venafi"},
				OrgUnits:   []string{"DevOps"},
				Localities: []string{"Salt Lake City"},
				States:     []string{"Utah"},
				Countries:  []string{"US"},
			},
			KeyPair: &policy.KeyPair{
				KeyTypes:         []string{"RSA"},
				RsaKeySizes:      []int{2048},
				ServiceGenerated: &serviceGenerated,
				ReuseAllowed:     &reuseAllowed,
				EllipticCurves:   []string{"P384"},
			},
			SubjectAltNames: &policy.SubjectAltNames{
				DnsAllowed:   &subjectAltNamesAllowed,
				IpAllowed:    &subjectAltNamesAllowed,
				EmailAllowed: &subjectAltNamesAllowed,
				UriAllowed:   &subjectAltNamesAllowed,
				UpnAllowed:   &upnAllowed,
				UriProtocols: []string{"https", "ldaps", "spiffe"},
			},
		},
		Default: &policy.Default{
			Domain: &domain,
			Subject: &policy.DefaultSubject{
				Org:      &org,
				OrgUnits: []string{"DevOps"},
				Locality: &locality,
				State:    &state,
				Country:  &country,
			},
			KeyPair: &policy.DefaultKeyPair{
				KeyType:          &defaultKeyType,
				RsaKeySize:       &defaultKeySize,
				EllipticCurve:    nil,
				ServiceGenerated: nil,
			},
		},
	}
	return &specification
}

func GetTppPolicySpecification() *policy.PolicySpecification {

	caName := os.Getenv("TPP_CA_NAME")
	validityHours := 120
	wildcardAllowed := true
	serviceGenerated := true
	reuseAllowed := false
	subjectAltNamesAllowedTrue := true
	subjectAltNamesAllowedFalse := false
	autoInstalled := true

	domain := "venafi.com"
	org := "Venafi"
	locality := "Salt Lake City"
	state := "Utah"
	country := "US"

	defaultKeyType := "RSA"
	defaultKeySize := 3072

	specification := policy.PolicySpecification{
		Policy: &policy.Policy{
			CertificateAuthority: &caName,
			Domains:              []string{"venafi.com"},
			WildcardAllowed:      &wildcardAllowed,
			MaxValidDays:         &validityHours,
			AutoInstalled:        &autoInstalled,
			Subject: &policy.Subject{
				Orgs:       []string{"Venafi"},
				OrgUnits:   []string{"DevOps"},
				Localities: []string{"Salt Lake City"},
				States:     []string{"Utah"},
				Countries:  []string{"US"},
			},
			KeyPair: &policy.KeyPair{
				KeyTypes:         []string{"RSA"},
				RsaKeySizes:      []int{3072},
				ServiceGenerated: &serviceGenerated,
				ReuseAllowed:     &reuseAllowed,
				EllipticCurves:   []string{"P384"},
			},
			SubjectAltNames: &policy.SubjectAltNames{
				DnsAllowed:   &subjectAltNamesAllowedTrue,
				IpAllowed:    &subjectAltNamesAllowedTrue,
				EmailAllowed: &subjectAltNamesAllowedFalse,
				UriAllowed:   &subjectAltNamesAllowedFalse,
				UpnAllowed:   &subjectAltNamesAllowedFalse,
			},
		},
		Default: &policy.Default{
			Domain:        &domain,
			AutoInstalled: &autoInstalled,
			Subject: &policy.DefaultSubject{
				Org:      &org,
				OrgUnits: []string{"DevOps"},
				Locality: &locality,
				State:    &state,
				Country:  &country,
			},
			KeyPair: &policy.DefaultKeyPair{
				KeyType:          &defaultKeyType,
				RsaKeySize:       &defaultKeySize,
				EllipticCurve:    nil,
				ServiceGenerated: nil,
			},
		},
	}
	return &specification
}

func IsArrayStringEqual(expectedValues, values []string) bool {

	if len(expectedValues) != len(values) {
		return false
	}

	for i, currentValue := range expectedValues {
		if currentValue != values[i] {
			return false
		}
	}

	return true
}

func StringArraysContainsSameValues(s1 []string, s2 []string) bool {
	if len(s1) != len(s2) {
		return false
	}

	for _, value1 := range s1 {
		found := false
		for _, value2 := range s2 {
			if value1 == value2 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func IsArrayIntEqual(expectedValues, values []int) bool {

	if len(expectedValues) != len(values) {
		return false
	}

	for i, currentValue := range expectedValues {

		if currentValue != values[i] {

			return false

		}

	}

	return true
}

func RandSshKeyId() string {
	return fmt.Sprintf("vcert-go-%d-%sSSHCert", time.Now().Unix(), randRunes(4))
}

type Certificate struct {
	ObjectName string
	CN         string
	Sans       []string
	Validity   time.Duration
	Zone       string
}

// represents a certificate with no CN
type CertificateNoCN struct {
	Certificate
}

// helper for generating certificates
func GenerateCertificate(r *rand.Rand, size int) Certificate {
	// generate a random CN
	cn := RandCN()
	return Certificate{
		// set the generated CN as the certificate's aswell as the object's name
		CN:         cn,
		ObjectName: cn,
		Validity:   3 * 24 * time.Hour,
		// for searching certificate, this is independent of the zone it will be created
		Zone: "Open Source\\vcert\\Search Certificate",
		// add 3 SAN-DNS prefixed with one, two and three respectively
		Sans: []string{Prefix("one", cn), Prefix("two", cn), Prefix("three", cn), cn},
	}
}

// GenerateCertificate wrapper for usage with quickcheck
func (Certificate) Generate(r *rand.Rand, s int) reflect.Value {
	return reflect.ValueOf(GenerateCertificate(r, s))
}

// GenerateCertificate wrapper for usage with quickcheck
func (CertificateNoCN) Generate(r *rand.Rand, s int) reflect.Value {
	c := GenerateCertificate(r, s)
	c.CN = ""
	return reflect.ValueOf(CertificateNoCN{c})
}

// adds prefix(es) `p` to a string `s`, using a dash character `-` as a delimiter
func Prefix(ps ...string) string {
	return strings.Join(ps, "-")
}

func (_c Certificate) ShuffleSans() Certificate {
	c := _c
	sans := c.Sans
	fmt.Printf("shuffling %v -> ", sans)
	rand.Shuffle(len(sans), func(i, j int) { sans[i], sans[j] = sans[j], sans[i] })
	c.Sans = sans
	fmt.Printf("%v\n", c.Sans)
	return c
}
