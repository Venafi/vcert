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

package cloud_validate

import (
	"fmt"
	"strconv"

	"github.com/Venafi/vcert/v4/pkg/policy"
)

var CloudRsaKeySize = []int{1024, 2048, 3072, 4096}

const (
	AllowAll = ".*"
)

func getSubjectAltNames(names policy.SubjectAltNames) map[string]bool {

	subjectAltNames := make(map[string]bool)

	if names.DnsAllowed != nil {
		subjectAltNames["dnsAllowed"] = *(names.DnsAllowed)
	}

	if names.IpAllowed != nil {
		subjectAltNames["ipAllowed"] = *(names.IpAllowed)
	}

	if names.EmailAllowed != nil {
		subjectAltNames["emailAllowed"] = *(names.EmailAllowed)
	}

	if names.UriAllowed != nil {
		subjectAltNames["uriAllowed"] = *(names.UriAllowed)
	}

	if names.UpnAllowed != nil {
		subjectAltNames["upnAllowed"] = *(names.UpnAllowed)
	}

	return subjectAltNames

}

func existStringInArray(userValue []string, supportedValues []string) bool {
	for _, uv := range userValue {
		match := false
		for _, sv := range supportedValues {
			if uv == sv {
				match = true
			}
		}
		if !match {
			return false
		}
	}
	return true
}

func existIntInArray(userValue []int, supportedValues []int) bool {
	for _, uv := range userValue {
		match := false
		for _, sv := range supportedValues {
			if uv == sv {
				match = true
			}
		}
		if !match {
			return false
		}
	}

	return true
}

func existValueInArray(array []string, value string) bool {
	for _, currentValue := range array {

		if currentValue == value {
			return true
		}

	}

	return false
}

func validateDefaultStringCloudValues(array []string, value string) bool {
	if len(array) == 1 {
		if array[0] == AllowAll { // this means that we are allowing everything
			return true
		}
	}
	return existValueInArray(array, value)
}

func getInvalidCloudRsaKeySizeValue(specifiedRSAKeys []int) *int {

	for _, currentUserVal := range specifiedRSAKeys {
		valid := false
		for _, rsaKey := range CloudRsaKeySize {
			if currentUserVal == rsaKey {
				valid = true
				break
			}
		}
		if !valid {
			return &currentUserVal
		}
	}
	return nil
}

func validateDefaultSubjectOrgsCloudValues(defaultValues []string, policyValues []string) bool {
	if len(policyValues) == 1 {
		if policyValues[0] == AllowAll { // this means that we are allowing everything
			return true
		}
	}
	return existStringInArray(defaultValues, policyValues)
}

func ValidateCloudPolicySpecification(ps *policy.PolicySpecification) error {

	//validate key type
	if ps.Policy != nil {
		if ps.Policy.KeyPair != nil {

			//validate key KeyTypes:keyLengths
			if len(ps.Policy.KeyPair.RsaKeySizes) > 0 {
				unSupported := getInvalidCloudRsaKeySizeValue(ps.Policy.KeyPair.RsaKeySizes)
				if unSupported != nil {
					return fmt.Errorf("specified attribute key length value: %s is not supported on VaaS", strconv.Itoa(*(unSupported)))
				}
			}
		}

		//validate subjectCNRegexes & sanRegexes
		if ps.Policy.SubjectAltNames != nil {
			subjectAltNames := getSubjectAltNames(*(ps.Policy.SubjectAltNames))
			if len(subjectAltNames) > 0 {
				for k, v := range subjectAltNames {
					if k == "upnAllowed" && v {
						return fmt.Errorf("specified subjectAltNames: %s value is true, this value is not allowed ", k)
					}
					if k == "uriAllowed" && v {
						if len(ps.Policy.SubjectAltNames.UriProtocols) == 0 {
							return fmt.Errorf("uriAllowed attribute is true, but uriProtocols is not specified or empty")
						}
					}
				}
			}
		}

		//if defaults are define validate that them matches with policy values
		if ps.Policy.Subject != nil {
			if ps.Default != nil && ps.Default.Subject != nil && ps.Default.Subject.Org != nil && len(ps.Policy.Subject.Orgs) > 0 {
				exist := validateDefaultStringCloudValues(ps.Policy.Subject.Orgs, *(ps.Default.Subject.Org))
				if !exist {
					return fmt.Errorf("specified default org value: %s  doesn't match with specified policy org", *(ps.Default.Subject.Org))
				}
			}

			if ps.Default != nil && ps.Default.Subject != nil && len(ps.Default.Subject.OrgUnits) > 0 && len(ps.Policy.Subject.OrgUnits) > 0 {
				exist := validateDefaultSubjectOrgsCloudValues(ps.Default.Subject.OrgUnits, ps.Policy.Subject.OrgUnits)
				if !exist {
					return fmt.Errorf("specified default org unit value: %s  doesn't match with specified policy org unit", *(ps.Default.Subject.Org))
				}
			}

			if ps.Default != nil && ps.Default.Subject != nil && ps.Default.Subject.Locality != nil && len(ps.Policy.Subject.Localities) > 0 {
				exist := validateDefaultStringCloudValues(ps.Policy.Subject.Localities, *(ps.Default.Subject.Locality))
				if !exist {
					return fmt.Errorf("specified default locality value: %s  doesn't match with specified policy locality", *(ps.Default.Subject.Locality))
				}
			}

			if ps.Default != nil && ps.Default.Subject != nil && ps.Default.Subject.State != nil && len(ps.Policy.Subject.States) > 0 {
				exist := validateDefaultStringCloudValues(ps.Policy.Subject.States, *(ps.Default.Subject.State))
				if !exist {
					return fmt.Errorf("specified default state value: %s  doesn't match with specified policy state", *(ps.Default.Subject.State))
				}
			}

			if ps.Default != nil && ps.Default.Subject != nil && ps.Default.Subject.Country != nil && len(ps.Policy.Subject.Countries) > 0 {
				exist := validateDefaultStringCloudValues(ps.Policy.Subject.Countries, *(ps.Default.Subject.Country))
				if !exist {
					return fmt.Errorf("specified default country value: %s  doesn't match with specified policy country", *(ps.Default.Subject.Country))
				}
			}
		}

		if ps.Policy.KeyPair != nil {
			if ps.Default != nil && ps.Default.KeyPair != nil && ps.Default.KeyPair.KeyType != nil && len(ps.Policy.KeyPair.KeyTypes) > 0 {
				exist := existValueInArray(ps.Policy.KeyPair.KeyTypes, *(ps.Default.KeyPair.KeyType))
				if !exist {
					return fmt.Errorf("specified default key type value: %s  doesn't match with specified policy key type", *(ps.Default.KeyPair.KeyType))
				}
			}

			if ps.Default != nil && ps.Default.KeyPair != nil && ps.Default.KeyPair.RsaKeySize != nil && len(ps.Policy.KeyPair.RsaKeySizes) > 0 {
				exist := existIntInArray([]int{*(ps.Default.KeyPair.RsaKeySize)}, ps.Policy.KeyPair.RsaKeySizes)
				if !exist {
					return fmt.Errorf("specified default rsa key size value: %s  doesn't match with specified policy rsa key size", strconv.Itoa(*(ps.Default.KeyPair.RsaKeySize)))
				}
			}
		}
	}

	//now in case that policy is empty but defaults key types and rsa sizes not, we need to validate them
	if ps.Default != nil && ps.Default.KeyPair != nil {

		if ps.Default.KeyPair.KeyType != nil && *(ps.Default.KeyPair.KeyType) != "" {
			if *(ps.Default.KeyPair.KeyType) != "RSA" && *(ps.Default.KeyPair.KeyType) != "EC" {
				return fmt.Errorf("specified default attribute keyType value is not supported on VaaS")
			}
		}

		//validate key KeyTypes:keyLengths
		if ps.Default.KeyPair.RsaKeySize != nil && *(ps.Default.KeyPair.RsaKeySize) != 0 {
			unSupported := getInvalidCloudRsaKeySizeValue([]int{*(ps.Default.KeyPair.RsaKeySize)})
			if unSupported != nil {
				return fmt.Errorf("specified attribute key length value: %s is not supported on VaaS", strconv.Itoa(*(unSupported)))
			}
		}
	}

	return nil
}
