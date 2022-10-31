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

package cloud_api

import "fmt"

type urlResource string

const (
	urlApplications      urlResource = "outagedetection/v1/applications"
	urlApplicationById   urlResource = "outagedetection/v1/applications/%s"
	urlApplicationByName urlResource = "outagedetection/v1/applications/name/%s"

	urlCertificateRequests    urlResource = "outagedetection/v1/certificaterequests"
	urlCertificateRequestById urlResource = "outagedetection/v1/certificaterequests/%s"

	urlCertificates           urlResource = "outagedetection/v1/certificates"
	urlCertificateById        urlResource = "outagedetection/v1/certificates/%s"
	urlCertificateRetrievePem urlResource = "outagedetection/v1/certificates/%s/contents"
	urlCertificateKS          urlResource = "outagedetection/v1/certificates/%s/keystore"

	urlCertificateSearch urlResource = "outagedetection/v1/certificatesearch"

	urlCertificateIssuingTemplates                  urlResource = "v1/certificateissuingtemplates"
	urlCertificateIssuingTemplateById               urlResource = "v1/certificateissuingtemplates/%s"
	urlCertificateIssuingTemplateByApplicationAndId urlResource = "outagedetection/v1/applications/%s/certificateissuingtemplates/%s"

	urlCaAccounts    urlResource = "v1/certificateauthorities/%s/accounts"
	urlCaAccountById urlResource = "v1/certificateauthorities/%s/accounts/%s"

	urlEdgeEncryptionKeyById urlResource = "v1/edgeencryptionkeys/%s"

	urlUserById    urlResource = "v1/users/%s"
	urlUsersByName urlResource = "v1/users/username/%s"

	urlUserAccounts urlResource = "v1/useraccounts"

	urlTeams urlResource = "v1/teams"
)

func (ur urlResource) Absolute(baseUrl string) urlResource {
	return urlResource(baseUrl + string(ur))
}

func (ur urlResource) Params(params ...interface{}) urlResource {
	return urlResource(fmt.Sprintf(string(ur), params...))
}
