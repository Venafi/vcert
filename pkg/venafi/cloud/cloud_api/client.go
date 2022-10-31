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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type RawClient struct {
	BaseUrl       string
	HttpClient    httpClient
	Authenticator func(*http.Request) error
}

var ua = fmt.Sprintf("vcert (%s/%s)", runtime.GOOS, runtime.GOARCH)

func newBytesRequest(method string, url string, reqObj interface{}) (*http.Request, error) {
	var payload io.Reader
	if ((method == "POST") || (method == "PUT")) && reqObj != nil {
		jsonBytes, err := json.Marshal(reqObj)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewBuffer(jsonBytes)
	}

	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")

	if (method == "POST") || (method == "PUT") {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}

	return req, err
}

func newRequest(method string, url string, reqObj interface{}) (*http.Request, error) {
	req, err := newBytesRequest(method, url, reqObj)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Charset", "utf-8")
	return req, err
}

func makeRawRequest(client httpClient, request *http.Request, fn func(response *http.Response, body io.Reader) error) error {
	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	statusOK := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !statusOK {
		return parseResponseErrors(resp.StatusCode, resp.Body)
	}

	if fn != nil {
		return fn(resp, resp.Body)
	}
	return nil
}

func makeRequest(client httpClient, request *http.Request, responseObject interface{}) error {
	return makeRawRequest(client, request, func(response *http.Response, body io.Reader) error {
		return json.NewDecoder(body).Decode(&responseObject)
	})
}
