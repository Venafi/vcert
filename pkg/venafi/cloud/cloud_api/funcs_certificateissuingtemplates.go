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

import (
	"net/http"

	"github.com/Venafi/vcert/v4/pkg/venafi/cloud/cloud_api/cloud_structs"
)

func (rc *RawClient) GetCertificateIssuingTemplates() (*cloud_structs.CertificateTemplates, error) {
	url := urlCertificateIssuingTemplates.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &cloud_structs.CertificateTemplates{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostCertificateIssuingTemplate(cit *cloud_structs.CloudPolicyRequest) (*cloud_structs.CertificateTemplates, error) {
	url := urlCertificateIssuingTemplates.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), cit)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &cloud_structs.CertificateTemplates{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PutCertificateIssuingTemplate(templateId string, cit *cloud_structs.CloudPolicyRequest) (*cloud_structs.CertificateTemplate, error) {
	url := urlCertificateIssuingTemplateById.Absolute(rc.BaseUrl).Params(templateId)

	req, err := newRequest(http.MethodPut, string(url), cit)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &cloud_structs.CertificateTemplate{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) GetCertificateIssuingTemplateByApplicationAndId(application string, templateId string) (*cloud_structs.CertificateTemplate, error) {
	url := urlCertificateIssuingTemplateByApplicationAndId.Absolute(rc.BaseUrl).Params(application, templateId)

	req, err := newRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &cloud_structs.CertificateTemplate{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}
