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
	"encoding/json"
	"io"
	"net/http"

	"github.com/Venafi/vcert/v4/pkg/venafi/cloud/cloud_api/cloud_structs"
)

func (rc *RawClient) GetUserById(userId string) (*cloud_structs.User, error) {
	url := urlUserById.Absolute(rc.BaseUrl).Params(userId)

	req, err := newRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &cloud_structs.User{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) GetUsersByName(name string) (*cloud_structs.Users, error) {
	url := urlUsersByName.Absolute(rc.BaseUrl).Params(name)

	req, err := newRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &cloud_structs.Users{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) GetUserAccounts() (*cloud_structs.UserDetails, error) {
	url := urlUserAccounts.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &cloud_structs.UserDetails{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostUserAccount(userAccount *cloud_structs.UserAccount) (*cloud_structs.UserDetails, error) {
	url := urlUserAccounts.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), userAccount)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &cloud_structs.UserDetails{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

// Deprecated: use PostUserAccount instead
func (rc *RawClient) PostUserAccountWithStatusCode(userAccount *cloud_structs.UserAccount) (int, *cloud_structs.UserDetails, error) {
	url := urlUserAccounts.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), userAccount)
	if err != nil {
		return 0, nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return 0, nil, err
	}

	responseStatusCode := 0
	responseObject := &cloud_structs.UserDetails{}

	if err := makeRawRequest(rc.HttpClient, req, func(response *http.Response, body io.Reader) error {
		responseStatusCode = response.StatusCode
		return json.NewDecoder(body).Decode(&responseObject)
	}); err != nil {
		return 0, nil, err
	}

	return responseStatusCode, responseObject, nil
}

func (rc *RawClient) GetTeams() (*cloud_structs.Teams, error) {
	url := urlTeams.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &cloud_structs.Teams{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}
