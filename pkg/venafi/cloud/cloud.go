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

package cloud

import (
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/Venafi/vcert/v4/pkg/util"
	"github.com/Venafi/vcert/v4/pkg/venafi/cloud/cloud_api/cloud_structs"

	"github.com/Venafi/vcert/v4/pkg/verror"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
)

const (
	UserOwnerType string = "USER"
	TeamOwnerType string = "TEAM"
)

// GenerateRequest generates a CertificateRequest based on the zone configuration, and returns the request along with the private key.
func (c *Connector) GenerateRequest(config *endpoint.ZoneConfiguration, req *certificate.Request) (err error) {
	switch req.CsrOrigin {
	case certificate.LocalGeneratedCSR:
		if config == nil {
			config, err = c.ReadZoneConfiguration()
			if err != nil {
				return fmt.Errorf("could not read zone configuration: %w", err)
			}
		}
		config.UpdateCertificateRequest(req)
		if err := req.GeneratePrivateKey(); err != nil {
			return err
		}
		err = req.GenerateCSR()
		return
	case certificate.UserProvidedCSR:
		if len(req.GetCSR()) == 0 {
			return fmt.Errorf("%w: CSR was supposed to be provided by user, but it's empty", verror.UserDataError)
		}
		return nil

	case certificate.ServiceGeneratedCSR:
		if req.KeyType == certificate.KeyTypeED25519 {
			return fmt.Errorf("%w: ED25519 keys are not yet supported for Service Generated CSR", verror.UserDataError)
		}
		return nil

	default:
		return fmt.Errorf("%w: unrecognised req.CsrOrigin %v", verror.UserDataError, req.CsrOrigin)
	}
}

func (c *Connector) getHTTPClient() *http.Client {
	if c.client != nil {
		return c.client
	}
	var netTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	tlsConfig := http.DefaultTransport.(*http.Transport).TLSClientConfig
	/* #nosec */
	if c.trust != nil {
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		} else {
			tlsConfig = tlsConfig.Clone()
		}
		tlsConfig.RootCAs = c.trust
	}
	netTransport.TLSClientConfig = tlsConfig
	c.client = &http.Client{
		Timeout:   time.Second * 30,
		Transport: netTransport,
	}
	return c.client
}

func newPEMCollectionFromResponse(data []byte, chainOrder certificate.ChainOption) (*certificate.PEMCollection, error) {
	return certificate.PEMCollectionFromBytes(data, chainOrder)
}

func certThumbprint(asn1 []byte) string {
	h := sha1.Sum(asn1)
	return strings.ToUpper(fmt.Sprintf("%x", h))
}

type cloudZone struct {
	zone          string
	appName       string
	templateAlias string
}

func (z cloudZone) String() string {
	return z.zone
}

func (z *cloudZone) getApplicationName() string {
	if z.appName == "" {
		err := z.parseZone()
		if err != nil {
			return ""
		}
	}
	return z.appName
}

func (z *cloudZone) getTemplateAlias() string {
	if z.templateAlias == "" {
		err := z.parseZone()
		if err != nil {
			return ""
		}
	}
	return z.templateAlias
}

func (z *cloudZone) parseZone() error {
	if z.zone == "" {
		return fmt.Errorf("zone not specified")
	}

	segments := strings.Split(z.zone, "\\")
	if len(segments) > 2 || len(segments) < 2 {
		return fmt.Errorf("invalid zone format")
	}

	z.appName = segments[0]
	z.templateAlias = segments[1]

	return nil
}

func createAppUpdateRequest(applicationDetails *cloud_structs.ApplicationDetails) cloud_structs.Application {
	request := cloud_structs.Application{
		OwnerIdsAndTypes:                     applicationDetails.OwnerIdsAndTypes,
		Name:                                 applicationDetails.Name,
		Description:                          applicationDetails.Description,
		Fqdns:                                applicationDetails.FqDns,
		InternalFqdns:                        applicationDetails.InternalFqDns,
		InternalIpRanges:                     applicationDetails.InternalIpRanges,
		ExternalIpRanges:                     applicationDetails.ExternalIpRanges,
		InternalPorts:                        applicationDetails.InternalPorts,
		FullyQualifiedDomainNames:            applicationDetails.FullyQualifiedDomainNames,
		IpRanges:                             applicationDetails.IpRanges,
		Ports:                                applicationDetails.Ports,
		CertificateIssuingTemplateAliasIdMap: applicationDetails.CertificateIssuingTemplateAliasIdMap,
	}

	return request
}

func getSAN(p *policy.Policy) *policy.SubjectAltNames {
	if p == nil || p.SubjectAltNames == nil {
		san := policy.SubjectAltNames{}
		p.SubjectAltNames = &san
		return &san
	}
	return p.SubjectAltNames
}

func removeRegex(values []string) []string {
	var regexVals []string
	for _, current := range values {

		current = strings.TrimPrefix(current, "[*a-z]{1}[a-z0-9.-]*\\.")
		current = strings.TrimPrefix(current, "[a-z]{1}[a-z0-9.-]*\\.")

		current = strings.ReplaceAll(current, "\\.", ".")

		regexVals = append(regexVals, current)
	}
	if len(regexVals) > 0 {
		return regexVals
	}

	return nil
}

func buildPolicySpecification(cit *cloud_structs.CertificateTemplate, info *policy.CertificateAuthorityInfo, doRemoveRegex bool) *policy.PolicySpecification {
	if cit == nil {
		return nil
	}

	var ps policy.PolicySpecification

	var pol policy.Policy

	if len(cit.SubjectCNRegexes) > 0 {
		if doRemoveRegex {
			pol.Domains = removeRegex(cit.SubjectCNRegexes)
		} else {
			pol.Domains = cit.SubjectCNRegexes
		}
	}

	wildCard := isWildCard(cit.SubjectCNRegexes)
	pol.WildcardAllowed = &wildCard

	if len(cit.SANRegexes) > 0 {
		subjectAlt := getSAN(&pol)
		subjectAlt.DnsAllowed = util.GetBooleanRef(true)
	}

	if len(cit.SanRfc822NameRegexes) > 0 {
		subjectAlt := getSAN(&pol)
		subjectAlt.EmailAllowed = util.GetBooleanRef(true)
	}

	if len(cit.SanUniformResourceIdentifierRegexes) > 0 {
		subjectAlt := getSAN(&pol)
		protocols := make([]string, 0)
		for _, val := range cit.SanUniformResourceIdentifierRegexes {
			index := strings.Index(val, ")://")
			subStr := val[1:index]
			currProtocols := strings.Split(subStr, "|")
			for _, currentProtocol := range currProtocols {
				if len(protocols) == 0 {
					protocols = append(protocols, currentProtocol)
				} else {
					if !contains(protocols, currentProtocol) {
						protocols = append(protocols, currentProtocol)
					}
				}
			}
		}
		subjectAlt.UriProtocols = protocols
		subjectAlt.UriAllowed = util.GetBooleanRef(true)
	}

	if len(cit.SanIpAddressRegexes) > 0 {
		subjectAlt := getSAN(&pol)
		subjectAlt.IpAllowed = util.GetBooleanRef(true)
	}

	// ps.Policy.WildcardAllowed is pending.
	if cit.ValidityPeriod != "" {
		//they have the format P#D
		days := cit.ValidityPeriod[1 : len(cit.ValidityPeriod)-1]
		intDays, _ := strconv.ParseInt(days, 10, 32)
		//ok we have a 32 bits int but we need to convert it just into a "int"
		intVal := int(intDays)
		pol.MaxValidDays = &intVal
	}
	if info != nil {
		ca := fmt.Sprint(info.CAType, "\\", info.CAAccountKey, "\\", info.VendorProductName)
		pol.CertificateAuthority = &ca
	}

	//subject.
	var subject policy.Subject

	if len(cit.SubjectORegexes) > 0 {
		subject.Orgs = cit.SubjectORegexes
	} else if cit.SubjectORegexes == nil {
		subject.Orgs = []string{""}
	}

	if len(cit.SubjectOURegexes) > 0 {
		subject.OrgUnits = cit.SubjectOURegexes
	} else if cit.SubjectOURegexes == nil {
		subject.OrgUnits = []string{""}
	}

	if len(cit.SubjectLRegexes) > 0 {
		subject.Localities = cit.SubjectLRegexes
	} else if cit.SubjectLRegexes == nil {
		subject.Localities = []string{""}
	}

	if len(cit.SubjectSTRegexes) > 0 {
		subject.States = cit.SubjectSTRegexes
	} else if cit.SubjectSTRegexes == nil {
		subject.States = []string{""}
	}

	if len(cit.SubjectCValues) > 0 {
		subject.Countries = cit.SubjectCValues
	} else if cit.SubjectCValues == nil {
		subject.Countries = []string{""}
	}

	pol.Subject = &subject

	//key pair
	var keyPair policy.KeyPair
	shouldCreateKeyPair := false
	if len(cit.KeyTypes) > 0 {
		var keyTypes []string
		var keySizes []int
		var ellipticCurves []string

		for _, allowedKT := range cit.KeyTypes {
			keyType := string(allowedKT.KeyType)
			keyLengths := allowedKT.KeyLengths
			ecKeys := allowedKT.KeyCurves

			keyTypes = append(keyTypes, keyType)

			if len(keyLengths) > 0 {
				keySizes = append(keySizes, keyLengths...)
			}

			if len(ecKeys) > 0 {
				ellipticCurves = append(ellipticCurves, ecKeys...)
			}

		}
		shouldCreateKeyPair = true
		keyPair.KeyTypes = keyTypes
		if len(keySizes) > 0 {
			keyPair.RsaKeySizes = keySizes
		}

		if len(ellipticCurves) > 0 {
			keyPair.EllipticCurves = ellipticCurves
		}
	}

	if cit.KeyGeneratedByVenafiAllowed && cit.CsrUploadAllowed {
		keyPair.ServiceGenerated = nil
	} else if cit.KeyGeneratedByVenafiAllowed {
		keyPair.ServiceGenerated = &cit.KeyGeneratedByVenafiAllowed
		shouldCreateKeyPair = true
	} else if cit.CsrUploadAllowed {
		falseVal := false
		keyPair.ServiceGenerated = &falseVal
		shouldCreateKeyPair = true
	}

	if shouldCreateKeyPair {
		pol.KeyPair = &keyPair
		pol.KeyPair.ReuseAllowed = &cit.KeyReuse
	}

	ps.Policy = &pol

	//build defaults.
	var defaultSub policy.DefaultSubject
	shouldCreateDeFaultSub := false
	if cit.RecommendedSettings.SubjectOValue != "" {
		defaultSub.Org = &cit.RecommendedSettings.SubjectOValue
		shouldCreateDeFaultSub = true
	}

	if cit.RecommendedSettings.SubjectOUValue != "" {
		defaultSub.OrgUnits = []string{cit.RecommendedSettings.SubjectOUValue}
		shouldCreateDeFaultSub = true
	}

	if cit.RecommendedSettings.SubjectCValue != "" {
		defaultSub.Country = &cit.RecommendedSettings.SubjectCValue
		shouldCreateDeFaultSub = true
	}

	if cit.RecommendedSettings.SubjectSTValue != "" {
		defaultSub.State = &cit.RecommendedSettings.SubjectSTValue
		shouldCreateDeFaultSub = true
	}

	if cit.RecommendedSettings.SubjectLValue != "" {
		defaultSub.Locality = &cit.RecommendedSettings.SubjectLValue
		shouldCreateDeFaultSub = true
	}

	if shouldCreateDeFaultSub {
		if ps.Default == nil {
			ps.Default = &policy.Default{}
		}
		ps.Default.Subject = &defaultSub
	}

	//default key type
	var defaultKP policy.DefaultKeyPair
	shouldCreateDefaultKeyPAir := false

	if cit.RecommendedSettings.Key.Type != "" {
		defaultKP.KeyType = &cit.RecommendedSettings.Key.Type
		shouldCreateDefaultKeyPAir = true
	}

	if cit.RecommendedSettings.Key.Length > 0 {
		defaultKP.RsaKeySize = &cit.RecommendedSettings.Key.Length
		shouldCreateDefaultKeyPAir = true
	}

	if cit.RecommendedSettings.Key.Curve != "" {
		defaultKP.EllipticCurve = &cit.RecommendedSettings.Key.Curve
		shouldCreateDefaultKeyPAir = true
	}

	if shouldCreateDefaultKeyPAir {
		if ps.Default == nil {
			ps.Default = &policy.Default{}
		}
		ps.Default.KeyPair = &defaultKP
	}

	return &ps
}

func contains(values []string, toSearch string) bool {
	copiedValues := make([]string, len(values))
	copy(copiedValues, values)
	sort.Strings(copiedValues)

	return binarySearch(copiedValues, toSearch) >= 0
}

func binarySearch(values []string, toSearch string) int {
	len := len(values) - 1
	min := 0
	for min <= len {
		mid := len - (len-min)/2
		if strings.Compare(toSearch, values[mid]) > 0 {
			min = mid + 1
		} else if strings.Compare(toSearch, values[mid]) < 0 {
			len = mid - 1
		} else {
			return mid
		}
	}
	return -1
}

func isWildCard(cnRegex []string) bool {
	if len(cnRegex) > 0 {
		for _, val := range cnRegex {
			if !(strings.HasPrefix(val, "[*a")) {
				return false
			}
		}
		return true
	}
	return false
}
