/*
 * Copyright 2023 Venafi, Inc.
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

package firefly

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/verror"
)

type urlResource string

const (
	urlResourceCertificateRequest    urlResource = "v1/certificaterequest"
	urlResourceCertificateRequestCSR urlResource = "v1/certificatesigningrequest"
)

type certificateRequest struct {
	CSR             string            `json:"request,omitempty"`
	Subject         Subject           `json:"subject,omitempty"`
	AlternativeName *AlternativeNames `json:"altNames,omitempty"`
	ValidityPeriod  *string           `json:"validityPeriod,omitempty"`
	PolicyName      string            `json:"policyName,omitempty"`
	KeyAlgorithm    string            `json:"keyType,omitempty"`
}

type Subject struct {
	CommonName   string   `json:"commonName,omitempty"`
	Organization string   `json:"organization,omitempty"`
	OrgUnits     []string `json:"orgUnits,omitempty"`
	Locality     string   `json:"locality,omitempty"`
	State        string   `json:"state,omitempty"`
	Country      string   `json:"country,omitempty"`
}

type AlternativeNames struct {
	DnsNames       []string `json:"dnsNames,omitempty"`
	IpAddresses    []string `json:"ipAddresses,omitempty"`
	EmailAddresses []string `json:"emailAddresses,omitempty"`
	Uris           []string `json:"uris,omitempty"`
}

type certificateRequestResponse struct {
	CertificateChain string `json:"certificateChain,omitempty"`
	PrivateKey       string `json:"privateKey"`
}

// GenerateRequest should generate a CertificateRequest based on the zone configuration when the csrOrigin was
// set to LocalGeneratedCSR but given that is not supported by Firefly yet, then it's only validating if the CSR
// was provided when the csrOrigin was set to UserProvidedCSR
func (c *Connector) GenerateRequest(_ *endpoint.ZoneConfiguration, req *certificate.Request) (err error) {
	switch req.CsrOrigin {
	case certificate.LocalGeneratedCSR:
		return fmt.Errorf("local generated CSR it's not supported by Firefly yet")
	case certificate.UserProvidedCSR:
		if len(req.GetCSR()) == 0 {
			return fmt.Errorf("%w: CSR was supposed to be provided by user, but it's empty", verror.UserDataError)
		}
		return nil

	case certificate.ServiceGeneratedCSR:
		return nil
	default:
		return fmt.Errorf("%w: unrecognised req.CsrOrigin %v", verror.UserDataError, req.CsrOrigin)
	}
}

func (c *Connector) request(method string, resource urlResource, data interface{}) (statusCode int, statusText string, body []byte, err error) {
	resourceUrl := c.baseURL + string(resource)
	var payload io.Reader
	var b []byte
	var values url.Values

	contentType := "application/json"

	if method == "POST" || method == "PUT" {
		//determining if the data is type of url.Values
		v, ok := data.(url.Values)
		//if the data is type of url.Values then commonly they are passed to the request as form
		if ok {
			payload = strings.NewReader(v.Encode())
			values = v
			contentType = "application/x-www-form-urlencoded"
		} else {
			b, _ = json.Marshal(data)
			payload = bytes.NewReader(b)
		}
	}

	r, _ := http.NewRequest(method, resourceUrl, payload)
	r.Close = true
	if c.accessToken != "" {
		r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
	}
	r.Header.Add("content-type", contentType)
	r.Header.Add("cache-control", "no-cache")

	res, err := c.getHTTPClient().Do(r)
	if res != nil {
		statusCode = res.StatusCode
		statusText = res.Status
	}
	if err != nil {
		return
	}

	defer res.Body.Close()
	body, err = ioutil.ReadAll(res.Body)
	// Do not enable trace in production
	trace := false // IMPORTANT: sensitive information can be diclosured
	// I hope you know what are you doing
	if trace {
		log.Println("#################")
		log.Printf("Headers are:\n%s", r.Header)
		if method == "POST" || method == "PUT" {
			if len(values) > 0 {
				log.Printf("Values sent for %s\n%s\n", resourceUrl, values.Encode())
			} else {
				log.Printf("JSON sent for %s\n%s\n", resourceUrl, string(b))
			}
		} else {
			log.Printf("%s request sent to %s\n", method, resourceUrl)
		}
		log.Printf("Response:\n%s\n", string(body))
	} else if c.verbose {
		log.Printf("Got %s status for %s %s\n", statusText, method, resourceUrl)
	}
	return
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

func parseCertificateRequestResult(httpStatusCode int, httpStatus string, body []byte) (*certificateRequestResponse, error) {
	switch httpStatusCode {
	case http.StatusOK:
		return parseCertificateRequestData(body)
	default:
		respError, err := NewResponseError(body)
		if err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("unexpected status code on Venafi Firefly. Status: %s error: %w", httpStatus, respError)
	}
}

func parseCertificateRequestData(b []byte) (*certificateRequestResponse, error) {
	var data certificateRequestResponse
	err := json.Unmarshal(b, &data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", verror.ServerError, err)
	}

	return &data, nil
}

func (c *Connector) getURL(resource urlResource) string {
	return fmt.Sprintf("%s%s", c.baseURL, resource)
}
