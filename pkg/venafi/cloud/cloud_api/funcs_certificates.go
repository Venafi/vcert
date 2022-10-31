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
	"io"
	"net/http"
	"time"

	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/cloud/cloud_api/cloud_structs"
)

func (rc *RawClient) GetCertificateById(certificateId string) (*cloud_structs.ManagedCertificate, error) {
	url := urlCertificateById.Absolute(rc.BaseUrl).Params(certificateId)

	req, err := newRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &cloud_structs.ManagedCertificate{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostCertificate(certificate *cloud_structs.ImportRequest) (*cloud_structs.ImportResponse, error) {
	url := urlCertificates.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), certificate)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &cloud_structs.ImportResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostCertificateKeyStore(certificateId string, certificate *cloud_structs.KeyStoreRequest) ([]byte, error) {
	url := urlCertificateKS.Absolute(rc.BaseUrl).Params(certificateId)

	req, err := newBytesRequest(http.MethodPost, string(url), certificate)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	var bytes []byte
	err = makeRawRequest(rc.HttpClient, req, func(_ *http.Response, body io.Reader) (err error) {
		bytes, err = io.ReadAll(body)
		return
	})
	return bytes, err
}

func (rc *RawClient) GetCertificateContents(certificateId string, query string) (*cloud_structs.EdgeEncryptionKey, error) {
	url := string(urlCertificateRetrievePem.Absolute(rc.BaseUrl).Params(certificateId)) + query

	req, err := newBytesRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &cloud_structs.EdgeEncryptionKey{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

// Waits for the Certificate to be available. Fails when the timeout is exceeded
func (rc *RawClient) WaitForCertificateContents(certificateId string, query string, timeout time.Duration) ([]byte, error) {
	url := string(urlCertificateRetrievePem.Absolute(rc.BaseUrl).Params(certificateId)) + query

	var bytes []byte
	startTime := time.Now()
	for {
		req, err := newBytesRequest(http.MethodGet, string(url), nil)
		if err != nil {
			return nil, err
		}

		if err := rc.Authenticator(req); err != nil {
			return nil, err
		}

		if err := makeRawRequest(rc.HttpClient, req, func(_ *http.Response, body io.Reader) (err error) {
			bytes, err = io.ReadAll(body)
			return
		}); err == nil {
			return bytes, nil
		}

		if timeout == 0 {
			return nil, endpoint.ErrCertificatePending{CertificateID: certificateId, Status: "TODO"}
		}

		if time.Now().After(startTime.Add(timeout)) {
			return nil, endpoint.ErrRetrieveCertificateTimeout{CertificateID: certificateId}
		}

		time.Sleep(2 * time.Second)
	}
}
