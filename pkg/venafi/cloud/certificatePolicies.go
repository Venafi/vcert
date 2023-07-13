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
	"strings"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/cloud/cloud_api/cloud_structs"
)

func certificateTemplateToPolicy(ct *cloud_structs.CertificateTemplate) (p endpoint.Policy) {
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
		if err := keyConfiguration.KeyType.Set(string(kt.KeyType), ""); err != nil {
			panic(err)
		}

		keyConfiguration.KeySizes = kt.KeyLengths[:]
		for _, keyCurve := range kt.KeyCurves {
			v := certificate.EllipticCurveNotSet
			if err := (&v).Set(keyCurve); err != nil {
				panic(err)
			}

			keyConfiguration.KeyCurves = append(keyConfiguration.KeyCurves, v)
		}
		p.AllowedKeyConfigurations = append(p.AllowedKeyConfigurations, keyConfiguration)
	}
	return
}

func certificateTemplateToZoneConfig(ct *cloud_structs.CertificateTemplate, zc *endpoint.ZoneConfiguration) {
	r := ct.RecommendedSettings
	zc.Country = r.SubjectCValue
	zc.Province = r.SubjectSTValue
	zc.Locality = r.SubjectLValue
	zc.Organization = r.SubjectOValue
	if r.SubjectOUValue != "" {
		zc.OrganizationalUnit = []string{r.SubjectOUValue}
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
