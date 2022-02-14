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
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"strings"
	"time"
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
	} `json:"product"`
	Priority               int              `json:"priority"`
	SystemGenerated        bool             `json:"systemGenerated,omitempty"`
	CreationDateString     string           `json:"creationDate,omitempty"`
	CreationDate           time.Time        `json:"-"`
	ModificationDateString string           `json:"modificationDate"`
	ModificationDate       time.Time        `json:"-"`
	Status                 string           `json:"status"`
	Reason                 string           `json:"reason"`
	SubjectCNRegexes       []string         `json:"subjectCNRegexes,omitempty"`
	SubjectORegexes        []string         `json:"subjectORegexes,omitempty"`
	SubjectOURegexes       []string         `json:"subjectOURegexes,omitempty"`
	SubjectSTRegexes       []string         `json:"subjectSTRegexes,omitempty"`
	SubjectLRegexes        []string         `json:"subjectLRegexes,omitempty"`
	SubjectCValues         []string         `json:"subjectCValues,omitempty"`
	SANRegexes             []string         `json:"sanRegexes,omitempty"`
	KeyTypes               []allowedKeyType `json:"keyTypes,omitempty"`
	KeyReuse               bool             `json:"keyReuse,omitempty"`
	RecommendedSettings    struct {
		SubjectOValue, SubjectOUValue,
		SubjectSTValue, SubjectLValue,
		SubjectCValue string
		Key struct {
			Type   string
			Length int
		}
		keyReuse bool
	}
	ValidityPeriod              string `json:"validityPeriod,omitempty"`
	CsrUploadAllowed            bool   `json:"csrUploadAllowed"`
	KeyGeneratedByVenafiAllowed bool   `json:"keyGeneratedByVenafiAllowed"`
}

type CertificateTemplates struct {
	CertificateTemplates []certificateTemplate `json:"certificateIssuingTemplates"`
}

type allowedKeyType struct {
	KeyType    keyType
	KeyLengths []int
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
		a := make([]string, len(ss))
		for i, s := range ss {
			a[i] = addStartEnd(s)
		}
		return a
	}
	if len(ct.SubjectCValues) == 0 {
		ct.SubjectCValues = []string{".*"}
	}
	p.SubjectCNRegexes = addStartEndToArray(ct.SubjectCNRegexes)
	p.SubjectOURegexes = addStartEndToArray(ct.SubjectOURegexes)
	p.SubjectCRegexes = addStartEndToArray(ct.SubjectCValues)
	p.SubjectSTRegexes = addStartEndToArray(ct.SubjectSTRegexes)
	p.SubjectLRegexes = addStartEndToArray(ct.SubjectLRegexes)
	p.SubjectORegexes = addStartEndToArray(ct.SubjectORegexes)
	p.DnsSanRegExs = addStartEndToArray(ct.SANRegexes)
	p.AllowKeyReuse = ct.KeyReuse
	allowWildCards := false
	for _, s := range p.SubjectCNRegexes {
		if strings.HasPrefix(s, `^.*`) {
			allowWildCards = true
		}
	}
	p.AllowWildcards = allowWildCards
	for _, kt := range ct.KeyTypes {
		keyConfiguration := endpoint.AllowedKeyConfiguration{}
		if err := keyConfiguration.KeyType.Set(string(kt.KeyType)); err != nil {
			panic(err)
		}
		keyConfiguration.KeySizes = kt.KeyLengths[:]
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
	key := endpoint.AllowedKeyConfiguration{}
	err := key.KeyType.Set(r.Key.Type)
	if err != nil {
		return
	}
	if r.Key.Length == 0 {
		return
	}
	key.KeySizes = []int{r.Key.Length}
	zc.KeyConfiguration = &key
}

/*
"signatureAlgorithm":{"type":"string","enum":["MD2_WITH_RSA_ENCRYPTION","MD5_WITH_RSA_ENCRYPTION","SHA1_WITH_RSA_ENCRYPTION","SHA1_WITH_RSA_ENCRYPTION2","SHA256_WITH_RSA_ENCRYPTION","SHA384_WITH_RSA_ENCRYPTION","SHA512_WITH_RSA_ENCRYPTION","ID_DSA_WITH_SHA1","dsaWithSHA1","EC_DSA_WITH_SHA1","EC_DSA_WITH_SHA224","EC_DSA_WITH_SHA256","EC_DSA_WITH_SHA384","EC_DSA_WITH_SHA512","UNKNOWN","SHA1_WITH_RSAandMGF1","GOST_R3411_94_WITH_GOST_R3410_2001","GOST_R3411_94_WITH_GOST_R3410_94"]},
"signatureHashAlgorithm":{"type":"string","enum":["MD5","SHA1","MD2","SHA224","SHA256","SHA384","SHA512","UNKNOWN","GOSTR3411_94"]}
*/
