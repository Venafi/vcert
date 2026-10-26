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

package ngts

import (
	"log"
	"strings"
	"time"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/policy"
)

type certificateTemplate struct {
	ID                                  string `json:"id,omitempty"`
	CompanyID                           string `json:"companyId,omitempty"`
	CertificateAuthority                string `json:"certificateAuthority"`
	Name                                string `json:"name,omitempty"`
	CertificateAuthorityAccountId       string `json:"certificateAuthorityAccountId"`
	CertificateAuthorityProductOptionId string `json:"certificateAuthorityProductOptionId"`
	Product                             struct {
		CertificateAuthority string `json:"certificateAuthority"`
		ProductName          string `json:"productName"`
		ValidityPeriod       string `json:"validityPeriod,omitempty"`
	} `json:"product"`
	Priority                            int              `json:"priority"`
	SystemGenerated                     bool             `json:"systemGenerated,omitempty"`
	CreationDateString                  string           `json:"creationDate,omitempty"`
	CreationDate                        time.Time        `json:"-"`
	ModificationDateString              string           `json:"modificationDate"`
	ModificationDate                    time.Time        `json:"-"`
	Status                              string           `json:"status"`
	Reason                              string           `json:"reason"`
	SubjectCNRegexes                    []string         `json:"subjectCNRegexes,omitempty"`
	SubjectORegexes                     []string         `json:"subjectORegexes,omitempty"`
	SubjectOURegexes                    []string         `json:"subjectOURegexes,omitempty"`
	SubjectSTRegexes                    []string         `json:"subjectSTRegexes,omitempty"`
	SubjectLRegexes                     []string         `json:"subjectLRegexes,omitempty"`
	SubjectCValues                      []string         `json:"subjectCValues,omitempty"`
	SANRegexes                          []string         `json:"sanRegexes,omitempty"`
	SanRfc822NameRegexes                []string         `json:"sanRfc822NameRegexes,omitempty"`
	SanIpAddressRegexes                 []string         `json:"sanIpAddressRegexes,omitempty"`
	SanUniformResourceIdentifierRegexes []string         `json:"sanUniformResourceIdentifierRegexes,omitempty"`
	KeyTypes                            []allowedKeyType `json:"keyTypes,omitempty"`
	// KeyAlgorithmTypes holds every allowed key type, including the ones that are not available in KeyTypes, such as
	// ML-DSA. KeyTypes only holds RSA and EC.
	KeyAlgorithmTypes   []allowedKeyType `json:"keyAlgorithmTypes,omitempty"`
	KeyReuse            bool             `json:"keyReuse,omitempty"`
	RecommendedSettings struct {
		SubjectOValue, SubjectOUValue,
		SubjectSTValue, SubjectLValue,
		SubjectCValue string
		// Key is the recommended RSA or EC key. It is empty when the recommended key is another key type, see
		// RecommendedKeyType
		Key struct {
			Type   string
			Length int
			Curve  string
		}
		RecommendedKeyType recommendedKeyType `json:"recommendedKeyType"`
		keyReuse           bool
	}
	ValidityPeriod              string `json:"validityPeriod,omitempty"`
	CsrUploadAllowed            bool   `json:"csrUploadAllowed"`
	KeyGeneratedByVenafiAllowed bool   `json:"keyGeneratedByVenafiAllowed"`
}

type CertificateTemplates struct {
	CertificateTemplates []certificateTemplate `json:"certificateIssuingTemplates"`
}

type allowedKeyType struct {
	KeyType      keyType
	KeyLengths   []int
	KeyCurves    []string `json:"keyCurves,omitempty"`
	KeyStrengths []int    `json:"keyStrengths,omitempty"`
}

// recommendedKeyType is the recommended key of an issuing template, which supports every key type
type recommendedKeyType struct {
	KeyType     string `json:"keyType"`
	KeyLength   int    `json:"keyLength,omitempty"`
	KeyCurve    string `json:"keyCurve,omitempty"`
	KeyStrength int    `json:"keyStrength,omitempty"`
}

// allowedKeyTypes returns the key types allowed by the issuing template, preferring keyAlgorithmTypes, which holds
// every key type, over the legacy keyTypes, which only holds RSA and EC
func (ct certificateTemplate) allowedKeyTypes() []allowedKeyType {
	if len(ct.KeyAlgorithmTypes) > 0 {
		return ct.KeyAlgorithmTypes
	}
	return ct.KeyTypes
}

type keyType string

func (ct certificateTemplate) toPolicy() (p endpoint.Policy) {
	addStartEnd := func(s string) string {
		if !strings.HasPrefix(s, "^") {
			s = "^" + s
		}
		if !strings.HasSuffix(s, "$") {
			s = s + "$"
		}
		return s
	}
	addStartEndToArray := func(ss []string) []string {
		// if the array is nil, return nil
		if ss == nil {
			return nil
		}

		a := make([]string, len(ss))
		for i, s := range ss {
			a[i] = addStartEnd(s)
		}
		return a
	}

	p.SubjectCNRegexes = addStartEndToArray(ct.SubjectCNRegexes)
	p.SubjectOURegexes = addStartEndToArray(ct.SubjectOURegexes)
	p.SubjectCRegexes = addStartEndToArray(ct.SubjectCValues) // For some reason, the API field is named subjectCValues instead of subjectCRegexes
	p.SubjectSTRegexes = addStartEndToArray(ct.SubjectSTRegexes)
	p.SubjectLRegexes = addStartEndToArray(ct.SubjectLRegexes)
	p.SubjectORegexes = addStartEndToArray(ct.SubjectORegexes)

	p.DnsSanRegExs = addStartEndToArray(ct.SANRegexes)
	p.IpSanRegExs = addStartEndToArray(ct.SanIpAddressRegexes)
	p.EmailSanRegExs = addStartEndToArray(ct.SanRfc822NameRegexes)
	p.UriSanRegExs = addStartEndToArray(ct.SanUniformResourceIdentifierRegexes)
	p.UpnSanRegExs = nil // UPN regexes are not provided by the API

	p.AllowKeyReuse = ct.KeyReuse
	allowWildCards := false
	for _, s := range p.SubjectCNRegexes {
		if strings.HasPrefix(s, `^.*`) {
			allowWildCards = true
		}
	}
	for _, s := range p.DnsSanRegExs {
		if strings.HasPrefix(s, `^.*`) {
			allowWildCards = true
		}
	}
	p.AllowWildcards = allowWildCards

	for _, kt := range ct.allowedKeyTypes() {
		if string(kt.KeyType) == policy.CloudKeyTypeMLDSA {
			// the ML-DSA strengths (44, 65, 87) are carried as key sizes, as in certificate.Request.KeyLength
			p.AllowedKeyConfigurations = append(p.AllowedKeyConfigurations, endpoint.AllowedKeyConfiguration{
				KeyType:  certificate.KeyTypeMLDSA,
				KeySizes: kt.KeyStrengths[:],
			})
			continue
		}
		keyConfiguration := endpoint.AllowedKeyConfiguration{}
		if err := keyConfiguration.KeyType.Set(string(kt.KeyType), ""); err != nil {
			// The issuing template may allow key types that this version of VCert doesn't know about. Skip them
			// rather than failing, so that the remaining key types can still be used.
			log.Printf("ignoring key type %q allowed by issuing template %q: not supported by this version of VCert", kt.KeyType, ct.Name)
			continue
		}

		keyConfiguration.KeySizes = kt.KeyLengths[:]
		for _, keyCurve := range kt.KeyCurves {
			v := certificate.EllipticCurveNotSet
			_ = (&v).Set(keyCurve)

			keyConfiguration.KeyCurves = append(keyConfiguration.KeyCurves, v)
		}
		p.AllowedKeyConfigurations = append(p.AllowedKeyConfigurations, keyConfiguration)
	}
	return
}

func (ct certificateTemplate) toZoneConfig(zc *endpoint.ZoneConfiguration) {
	r := ct.RecommendedSettings
	zc.Country = r.SubjectCValue
	zc.Province = r.SubjectSTValue
	zc.Locality = r.SubjectLValue
	zc.Organization = r.SubjectOValue
	if r.SubjectOUValue != "" {
		zc.OrganizationalUnit = []string{r.SubjectOUValue}
	}
	if rk := r.RecommendedKeyType; rk.KeyType != "" {
		zc.KeyConfiguration = rk.toKeyConfiguration()
		return
	}
	key := endpoint.AllowedKeyConfiguration{}
	err := key.KeyType.Set(r.Key.Type, r.Key.Curve)
	if err != nil {
		return
	}
	if r.Key.Length == 0 {
		return
	}
	key.KeySizes = []int{r.Key.Length}
	zc.KeyConfiguration = &key
}

// toKeyConfiguration converts the recommended key to a key configuration. It returns nil when VCert doesn't support
// the recommended key type
func (rk recommendedKeyType) toKeyConfiguration() *endpoint.AllowedKeyConfiguration {
	if rk.KeyType == policy.CloudKeyTypeMLDSA {
		return &endpoint.AllowedKeyConfiguration{KeyType: certificate.KeyTypeMLDSA, KeySizes: []int{rk.KeyStrength}}
	}
	key := endpoint.AllowedKeyConfiguration{}
	if err := key.KeyType.Set(rk.KeyType, rk.KeyCurve); err != nil {
		return nil
	}
	if rk.KeyLength > 0 {
		key.KeySizes = []int{rk.KeyLength}
	}
	if rk.KeyCurve != "" && key.KeyType == certificate.KeyTypeECDSA {
		curve := certificate.EllipticCurveNotSet
		_ = curve.Set(rk.KeyCurve)
		key.KeyCurves = []certificate.EllipticCurve{curve}
	}
	return &key
}

/*
"signatureAlgorithm":{"type":"string","enum":["MD2_WITH_RSA_ENCRYPTION","MD5_WITH_RSA_ENCRYPTION","SHA1_WITH_RSA_ENCRYPTION","SHA1_WITH_RSA_ENCRYPTION2","SHA256_WITH_RSA_ENCRYPTION","SHA384_WITH_RSA_ENCRYPTION","SHA512_WITH_RSA_ENCRYPTION","ID_DSA_WITH_SHA1","dsaWithSHA1","EC_DSA_WITH_SHA1","EC_DSA_WITH_SHA224","EC_DSA_WITH_SHA256","EC_DSA_WITH_SHA384","EC_DSA_WITH_SHA512","UNKNOWN","SHA1_WITH_RSAandMGF1","GOST_R3411_94_WITH_GOST_R3410_2001","GOST_R3411_94_WITH_GOST_R3410_94"]},
"signatureHashAlgorithm":{"type":"string","enum":["MD5","SHA1","MD2","SHA224","SHA256","SHA384","SHA512","UNKNOWN","GOSTR3411_94"]}
*/
