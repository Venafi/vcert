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

func (rc *RawClient) GetApplicationByName(name string) (*cloud_structs.ApplicationDetails, error) {
	url := urlApplicationByName.Absolute(rc.BaseUrl).Params(name)

	req, err := newRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &cloud_structs.ApplicationDetails{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostApplication(application *cloud_structs.Application) error {
	url := urlApplications.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), application)
	if err != nil {
		return err
	}

	if err := rc.Authenticator(req); err != nil {
		return err
	}

	return makeRequest(rc.HttpClient, req, nil)
}

func (rc *RawClient) PutApplication(applicationId string, application *cloud_structs.Application) error {
	url := urlApplicationById.Absolute(rc.BaseUrl).Params(applicationId)

	req, err := newRequest(http.MethodPut, string(url), application)
	if err != nil {
		return err
	}

	if err := rc.Authenticator(req); err != nil {
		return err
	}

	return makeRequest(rc.HttpClient, req, nil)
}
