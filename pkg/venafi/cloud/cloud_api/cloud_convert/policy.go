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
	"fmt"
	"strconv"
	"strings"

	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/Venafi/vcert/v4/pkg/venafi/cloud/cloud_api/cloud_structs"
)

const (
	CloudEntrustCA      = "ENTRUST"
	CloudDigicertCA     = "DIGICERT"
	CloudRequesterName  = "Venafi Cloud Service"
	CloudRequesterEmail = "no-reply@venafi.cloud"
	CloudRequesterPhone = "801-555-0123"

	ipv4      = "\\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\.|$)){4}\\b"
	ipv6      = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
	v4private = "^(172\\.(1[6-9]\\.|2[0-9]\\.|3[0-1]\\.)|192\\.168\\.|10\\.).*"
	v6private = "^(::1$)|([fF][cCdD]).*"
)

func BuildCloudCitRequest(ps *policy.PolicySpecification, ca *policy.CADetails) (*cloud_structs.CloudPolicyRequest, error) {
	var cloudPolicyRequest cloud_structs.CloudPolicyRequest
	var certAuth policy.CertificateAuthorityInfo
	var err error
	var period int
	if ps.Policy != nil && ps.Policy.CertificateAuthority != nil && *(ps.Policy.CertificateAuthority) != "" {
		certAuth, err = GetCertAuthorityInfo(*(ps.Policy.CertificateAuthority))
		if err != nil {
			return nil, err
		}
	} else {
		certAuth, err = GetCertAuthorityInfo(policy.DefaultCA)
		if err != nil {
			return nil, err
		}
	}

	cloudPolicyRequest.CertificateAuthority = certAuth.CAType
	cloudPolicyRequest.CertificateAuthorityProductOptionId = *(ca.CertificateAuthorityProductOptionId)

	if ps.Policy != nil && ps.Policy.MaxValidDays != nil {
		period = *(ps.Policy.MaxValidDays)
		if period == 0 {
			period = 365
		}
	} else {
		period = 365
	}

	product := cloud_structs.Product{
		CertificateAuthority: certAuth.CAType,
		ProductName:          certAuth.VendorProductName,
		ValidityPeriod:       fmt.Sprint("P", strconv.Itoa(period), "D"),
	}

	if certAuth.CAType == CloudDigicertCA {
		alg := "SHA256"
		autoRen := false
		product.HashAlgorithm = &alg
		product.AutoRenew = &autoRen
		product.OrganizationId = ca.CertificateAuthorityOrganizationId
	}

	if certAuth.CAType == CloudEntrustCA {
		td := cloud_structs.TrackingData{
			CertificateAuthority: CloudEntrustCA,
			RequesterName:        CloudRequesterName,
			RequesterEmail:       CloudRequesterEmail,
			RequesterPhone:       CloudRequesterPhone,
		}
		cloudPolicyRequest.TrackingData = &td
	}

	cloudPolicyRequest.Product = product

	if ps.Policy != nil && len(ps.Policy.Domains) > 0 {
		regexValues := convertToRegex(ps.Policy.Domains, isWildcardAllowed(*(ps)))
		cloudPolicyRequest.SubjectCNRegexes = regexValues
		if ps.Policy.SubjectAltNames != nil && ps.Policy.SubjectAltNames.DnsAllowed != nil {
			if *(ps.Policy.SubjectAltNames.DnsAllowed) {
				cloudPolicyRequest.SanRegexes = regexValues //in cloud subject CN and SAN have the same values and we use domains as those values
			} else {
				cloudPolicyRequest.SanRegexes = nil
			}
		} else {
			cloudPolicyRequest.SanRegexes = regexValues //in cloud subject CN and SAN have the same values and we use domains as those values
		}

		if ps.Policy.SubjectAltNames != nil && ps.Policy.SubjectAltNames.EmailAllowed != nil {
			if *(ps.Policy.SubjectAltNames.EmailAllowed) {
				rfc882Regex := convertToRfc822Regex(ps.Policy.Domains)
				cloudPolicyRequest.SanRfc822NameRegexes = rfc882Regex
			} else {
				cloudPolicyRequest.SanRfc822NameRegexes = nil
			}
		}

		if ps.Policy != nil && ps.Policy.SubjectAltNames != nil && len(ps.Policy.SubjectAltNames.UriProtocols) > 0 {
			uriRegex := convertToUriRegex(ps.Policy.SubjectAltNames.UriProtocols, ps.Policy.Domains)
			cloudPolicyRequest.SanUniformResourceIdentifierRegexes = uriRegex
		}

	} else {
		cloudPolicyRequest.SubjectCNRegexes = []string{".*"}
		cloudPolicyRequest.SanRegexes = []string{".*"}

		if ps.Policy != nil {
			if ps.Policy.SubjectAltNames != nil && ps.Policy.SubjectAltNames.EmailAllowed != nil {
				if *(ps.Policy.SubjectAltNames.EmailAllowed) {
					cloudPolicyRequest.SanRfc822NameRegexes = []string{".*@.*"}
				}
			}

			if ps.Policy.SubjectAltNames != nil && ps.Policy.SubjectAltNames.IpAllowed != nil {
				if *(ps.Policy.SubjectAltNames.IpAllowed) {
					cloudPolicyRequest.SanIpAddressRegexes = []string{}
				}
			}

			//to be implemented.
			if ps.Policy != nil && ps.Policy.SubjectAltNames != nil && len(ps.Policy.SubjectAltNames.UriProtocols) > 0 {
				uriRegex := convertToUriRegex(ps.Policy.SubjectAltNames.UriProtocols, []string{".*"})
				cloudPolicyRequest.SanUniformResourceIdentifierRegexes = uriRegex
			}

		}
	}

	if ps.Policy != nil && ps.Policy.SubjectAltNames != nil && ps.Policy.SubjectAltNames.IpAllowed != nil {
		if *(ps.Policy.SubjectAltNames.IpAllowed) {
			if len(ps.Policy.SubjectAltNames.IpConstraints) > 0 {
				cloudPolicyRequest.SanIpAddressRegexes = getIpRegexes(ps.Policy.SubjectAltNames.IpConstraints)
			} else {
				cloudPolicyRequest.SanIpAddressRegexes = []string{
					ipv4, ipv6,
				}
			}

		} else {
			cloudPolicyRequest.SanIpAddressRegexes = nil
		}
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.Orgs) > 0 {
		if len(ps.Policy.Subject.Orgs) == 1 && ps.Policy.Subject.Orgs[0] == "" {
			cloudPolicyRequest.SubjectORegexes = nil
		} else {
			cloudPolicyRequest.SubjectORegexes = ps.Policy.Subject.Orgs
		}

	} else {
		cloudPolicyRequest.SubjectORegexes = []string{".*"}
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.OrgUnits) > 0 {
		if len(ps.Policy.Subject.OrgUnits) == 1 && ps.Policy.Subject.OrgUnits[0] == "" {
			cloudPolicyRequest.SubjectOURegexes = nil
		} else {
			cloudPolicyRequest.SubjectOURegexes = ps.Policy.Subject.OrgUnits
		}

	} else {
		cloudPolicyRequest.SubjectOURegexes = []string{".*"}
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.Localities) > 0 {
		if len(ps.Policy.Subject.Localities) == 1 && ps.Policy.Subject.Localities[0] == "" {
			cloudPolicyRequest.SubjectLRegexes = nil
		} else {
			cloudPolicyRequest.SubjectLRegexes = ps.Policy.Subject.Localities
		}

	} else {
		cloudPolicyRequest.SubjectLRegexes = []string{".*"}
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.States) > 0 {
		if len(ps.Policy.Subject.States) == 1 && ps.Policy.Subject.States[0] == "" {
			cloudPolicyRequest.SubjectSTRegexes = nil
		} else {
			cloudPolicyRequest.SubjectSTRegexes = ps.Policy.Subject.States
		}
	} else {
		cloudPolicyRequest.SubjectSTRegexes = []string{".*"}
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.Countries) > 0 {
		if len(ps.Policy.Subject.Countries) == 1 && ps.Policy.Subject.Countries[0] == "" {
			cloudPolicyRequest.SubjectCValues = nil
		} else {
			cloudPolicyRequest.SubjectCValues = ps.Policy.Subject.Countries
		}
	} else {
		cloudPolicyRequest.SubjectCValues = []string{".*"}
	}

	var keyType *cloud_structs.KeyType
	var ecKeyType *cloud_structs.KeyType
	if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.KeyTypes) > 0 {
		for _, val := range ps.Policy.KeyPair.KeyTypes {
			if val == "RSA" {
				keyType = &cloud_structs.KeyType{}
				keyType.KeyType = val
			} else if val == "EC" {
				ecKeyType = &cloud_structs.KeyType{}
				ecKeyType.KeyType = val
			}
		}

	} else {
		keyType = &cloud_structs.KeyType{}
		keyType.KeyType = "RSA"
	}

	if keyType != nil {
		if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.RsaKeySizes) > 0 {
			keyType.KeyLengths = ps.Policy.KeyPair.RsaKeySizes
		} else {
			// on this case we need to look if there is a default if so then we can use it.
			if ps.Default != nil && ps.Default.KeyPair != nil && ps.Default.KeyPair.RsaKeySize != nil {
				keyType.KeyLengths = []int{*(ps.Default.KeyPair.RsaKeySize)}
			} else {
				keyType.KeyLengths = []int{2048}
			}

		}
	}

	if ecKeyType != nil {
		if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.EllipticCurves) > 0 {
			ecKeyType.KeyCurves = ps.Policy.KeyPair.EllipticCurves
		} else {
			// on this case we need to look if there is a default if so then we can use it.
			if ps.Default != nil && ps.Default.KeyPair != nil && ps.Default.KeyPair.EllipticCurve != nil {
				ecKeyType.KeyCurves = []string{*(ps.Default.KeyPair.EllipticCurve)}
			} else {
				ecKeyType.KeyCurves = []string{"P256"}
			}
		}
	}

	var keyTypesArr []cloud_structs.KeyType

	if keyType != nil {
		keyTypesArr = append(keyTypesArr, *(keyType))
	}

	if ecKeyType != nil {
		keyTypesArr = append(keyTypesArr, *(ecKeyType))
	}

	if len(keyTypesArr) > 0 {
		cloudPolicyRequest.KeyTypes = keyTypesArr
	}

	if ps.Policy != nil && ps.Policy.KeyPair != nil && ps.Policy.KeyPair.ReuseAllowed != nil {
		cloudPolicyRequest.KeyReuse = ps.Policy.KeyPair.ReuseAllowed
	} else {
		falseValue := false
		cloudPolicyRequest.KeyReuse = &falseValue
	}

	//build recommended settings

	var recommendedSettings cloud_structs.RecommendedSettings
	shouldCreateSubjectRS := false
	shouldCreateKPRS := false

	/*if ps.Default.Domain != nil { ignore for now
		recommendedSettings.SubjectCNRegexes = []string{*(ps.Default.Domain)}//whan value should be put here.
		shouldCreateSubjectRS = true
	}*/
	if ps.Default != nil && ps.Default.Subject != nil {
		if ps.Default.Subject.Org != nil {
			recommendedSettings.SubjectOValue = ps.Default.Subject.Org
			shouldCreateSubjectRS = true
		}
		if ps.Default.Subject.OrgUnits != nil {
			recommendedSettings.SubjectOUValue = &ps.Default.Subject.OrgUnits[0]
			shouldCreateSubjectRS = true
		}
		if ps.Default.Subject.Locality != nil {
			recommendedSettings.SubjectLValue = ps.Default.Subject.Locality
			shouldCreateSubjectRS = true
		}
		if ps.Default.Subject.State != nil {
			recommendedSettings.SubjectSTValue = ps.Default.Subject.State
			shouldCreateSubjectRS = true
		}

		if ps.Default.Subject.Country != nil {
			recommendedSettings.SubjectCValue = ps.Default.Subject.Country
			shouldCreateSubjectRS = true
		}
	}

	var key cloud_structs.Key
	if ps.Default != nil && ps.Default.KeyPair != nil {
		if ps.Default.KeyPair.KeyType != nil {

			key.Type = *(ps.Default.KeyPair.KeyType)
			if key.Type == "RSA" {
				if ps.Default.KeyPair.RsaKeySize != nil {
					key.Length = *(ps.Default.KeyPair.RsaKeySize)
				} else {
					//default
					key.Length = 2048
				}
			} else if key.Type == "EC" {
				if ps.Default.KeyPair.EllipticCurve != nil && *(ps.Default.KeyPair.EllipticCurve) != "" {
					key.Curve = *(ps.Default.KeyPair.EllipticCurve)
				} else {
					key.Curve = "P256"
				}
			}

			shouldCreateKPRS = true
		}
	}
	//SanRegexes is ignored now.

	if shouldCreateKPRS {
		recommendedSettings.Key = &key
	}

	if shouldCreateKPRS || shouldCreateSubjectRS {
		cloudPolicyRequest.RecommendedSettings = &recommendedSettings
	}

	if ps.Policy != nil && ps.Policy.KeyPair != nil && ps.Policy.KeyPair.ServiceGenerated != nil {
		cloudPolicyRequest.CsrUploadAllowed = !*(ps.Policy.KeyPair.ServiceGenerated)
		cloudPolicyRequest.KeyGeneratedByVenafiAllowed = *(ps.Policy.KeyPair.ServiceGenerated)
	} else {
		cloudPolicyRequest.CsrUploadAllowed = true
		cloudPolicyRequest.KeyGeneratedByVenafiAllowed = true
	}

	return &cloudPolicyRequest, nil
}

func GetCertAuthorityInfo(certificateAuthority string) (policy.CertificateAuthorityInfo, error) {
	var caInfo policy.CertificateAuthorityInfo
	data := strings.Split(certificateAuthority, "\\")

	if len(data) < 3 {
		return caInfo, fmt.Errorf("certificate Authority is invalid, please provide a valid value with this structure: ca_type\\ca_account_key\\vendor_product_name")
	}

	caInfo = policy.CertificateAuthorityInfo{
		CAType:            data[0],
		CAAccountKey:      data[1],
		VendorProductName: data[2],
	}

	return caInfo, nil
}

func convertToRegex(values []string, wildcardAllowed bool) []string {
	var regexVals []string
	for _, current := range values {
		currentRegex := strings.ReplaceAll(current, ".", "\\.")
		if wildcardAllowed {
			currentRegex = fmt.Sprint("[*a-z]{1}[a-z0-9.-]*\\.", currentRegex)
		} else {
			currentRegex = fmt.Sprint("[a-z]{1}[a-z0-9.-]*\\.", currentRegex)
		}
		regexVals = append(regexVals, currentRegex)
	}
	if len(regexVals) > 0 {
		return regexVals
	}

	return nil
}

func isWildcardAllowed(ps policy.PolicySpecification) bool {
	if ps.Policy != nil && ps.Policy.WildcardAllowed != nil {
		return *(ps.Policy.WildcardAllowed)
	}
	return false
}

func convertToRfc822Regex(values []string) []string {
	var regexVals []string
	for _, current := range values {

		currentRegex := strings.ReplaceAll(current, ".", "\\.")
		currentRegex = fmt.Sprint(".*@", currentRegex)

		regexVals = append(regexVals, currentRegex)
	}

	if len(regexVals) > 0 {
		return regexVals
	}

	return nil
}

func convertToUriRegex(protocols, domains []string) []string {
	var regexVals []string

	protocolsS := strings.Join(protocols, "|")
	protocolsS = fmt.Sprint("(", protocolsS, ")://.*\\.")

	for _, current := range domains {

		currentRegex := strings.ReplaceAll(current, ".", "\\.")
		currentRegex = fmt.Sprint(protocolsS, currentRegex)

		regexVals = append(regexVals, currentRegex)
	}

	if len(regexVals) > 0 {
		return regexVals
	}

	return nil
}

func getIpRegexes(supportedIps []string) (ipRegexes []string) {
	ipRegexes = make([]string, 0)

	for _, val := range supportedIps {

		if val == "v4" {
			ipRegexes = append(ipRegexes, ipv4)
		}
		if val == "v6" {
			ipRegexes = append(ipRegexes, ipv6)

		}
		if val == "v4private" {
			ipRegexes = append(ipRegexes, v4private)

		}
		if val == "v6private" {
			ipRegexes = append(ipRegexes, v6private)

		}
	}

	return ipRegexes
}
