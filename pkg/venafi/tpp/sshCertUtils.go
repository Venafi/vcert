/*
 * Copyright 2018-2021 Venafi, Inc.
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
package tpp

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	netUrl "net/url"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/util"
)

const (
	SSHCaRootPath = util.PathSeparator + "VED" + util.PathSeparator + "Certificate Authority" + util.PathSeparator + "SSH" + util.PathSeparator + "Templates"
)

func RequestSshCertificate(c *Connector, req *certificate.SshCertRequest) (*certificate.SshCertificateObject, error) {

	sshCertReq := convertToSshCertReq(req)

	if sshCertReq.KeyId == "" {
		log.Println("Requesting SSH certificate from ", sshCertReq.CADN)
	} else {
		log.Println("Requesting SSH certificate with certificate identifier: ", sshCertReq.KeyId)
	}

	//TODO: Maybe, there is a better way to set the timeout.
	c.client.Timeout = time.Duration(req.Timeout) * time.Second
	statusCode, status, body, err := c.request("POST", urlResourceSshCertReq, sshCertReq)
	if err != nil {
		return nil, err
	}

	response, err := parseSshCertOperationResponse(statusCode, status, body)

	if err != nil {
		if response.Response.ErrorMessage != "" && c.verbose {
			log.Println(util.GetJsonAsString(response.Response))
		}
		return nil, err
	}

	log.Println("SSH certificate DN: ", response.DN)
	log.Println("GUID: ", response.Guid)

	if response.Response.Success && response.ProcessingDetails.Status == "Rejected" {
		return nil, endpoint.ErrCertificateRejected{CertificateID: req.PickupID, Status: response.ProcessingDetails.StatusDescription}
	}

	return convertToGenericRetrieveResponse(&response), nil
}

func convertToSshCertReq(req *certificate.SshCertRequest) certificate.TPPSshCertRequest {

	var tppSshCertReq certificate.TPPSshCertRequest

	if len(req.Principals) > 0 {
		tppSshCertReq.Principals = req.Principals
	}

	if len(req.Extensions) > 0 {

		tppSshCertReq.Extensions = make(map[string]interface{})

		for _, extension := range req.Extensions {

			data := strings.Split(extension, ":")

			key := data[0]
			value := ""

			//if value is specified then get it.
			if len(data) > 1 {
				value = data[1]
			}

			tppSshCertReq.Extensions[key] = value

		}
	}

	if req.PolicyDN != "" {
		tppSshCertReq.PolicyDN = req.PolicyDN
	}

	if req.ObjectName != "" {
		tppSshCertReq.ObjectName = req.ObjectName
	}

	if len(req.DestinationAddresses) > 0 {
		tppSshCertReq.DestinationAddresses = req.DestinationAddresses
	}

	if req.KeyId != "" {
		tppSshCertReq.KeyId = req.KeyId
	}

	if req.ValidityPeriod != "" {
		tppSshCertReq.ValidityPeriod = req.ValidityPeriod
	}

	if len(req.SourceAddresses) > 0 {
		tppSshCertReq.SourceAddresses = req.SourceAddresses
	}

	if req.PublicKeyData != "" {
		tppSshCertReq.PublicKeyData = req.PublicKeyData
	}

	if req.Template != "" {
		tppSshCertReq.CADN = getSshCaDN(req.Template)
	}

	if req.ForceCommand != "" {
		tppSshCertReq.ForceCommand = req.ForceCommand
	}

	tppSshCertReq.IncludePrivateKeyData = true
	tppSshCertReq.IncludeCertificateDetails = true

	return tppSshCertReq
}

func RetrieveSshCertificate(c *Connector, req *certificate.SshCertRequest) (*certificate.SshCertificateObject, error) {
	var reqRetrieve certificate.TppSshCertRetrieveRequest

	if req.PickupID != "" {
		reqRetrieve.DN = req.PickupID
	}

	if req.Guid != "" {
		reqRetrieve.Guid = req.Guid
	}

	if req.PrivateKeyPassphrase != "" {
		reqRetrieve.PrivateKeyPassphrase = req.PrivateKeyPassphrase
	}

	//this values are always true
	reqRetrieve.IncludePrivateKeyData = true
	reqRetrieve.IncludeCertificateDetails = true

	startTime := time.Now()
	for {
		var retrieveResponse *certificate.TppSshCertOperationResponse
		retrieveResponse, err := retrieveSshCerOnce(reqRetrieve, c)
		if err != nil {
			return nil, err
		}
		if retrieveResponse.CertificateData != "" {
			return convertToGenericRetrieveResponse(retrieveResponse), nil
		}

		if retrieveResponse.Response.Success && retrieveResponse.ProcessingDetails.Status == "Rejected" {
			return nil, endpoint.ErrCertificateRejected{CertificateID: req.PickupID, Status: retrieveResponse.ProcessingDetails.StatusDescription}
		}

		if req.Timeout == 0 {
			return nil, endpoint.ErrCertificatePending{CertificateID: req.PickupID, Status: retrieveResponse.ProcessingDetails.StatusDescription}
		}
		if time.Now().After(startTime.Add(req.Timeout)) {
			return nil, endpoint.ErrRetrieveCertificateTimeout{CertificateID: req.PickupID}
		}
		time.Sleep(2 * time.Second)
	}
}

func retrieveSshCerOnce(sshRetrieveReq certificate.TppSshCertRetrieveRequest, c *Connector) (*certificate.TppSshCertOperationResponse, error) {
	statusCode, status, body, err := c.request("POST", urlResourceSshCertRet, sshRetrieveReq)
	if err != nil {
		return nil, err
	}
	retrieveResponse, err := parseSshCertOperationResponse(statusCode, status, body)
	if err != nil {
		return nil, err
	}
	return &retrieveResponse, nil
}

func parseSshCertOperationResponse(httpStatusCode int, httpStatus string, body []byte) (certificate.TppSshCertOperationResponse, error) {
	var retrieveResponse certificate.TppSshCertOperationResponse
	switch httpStatusCode {
	case http.StatusOK, http.StatusAccepted:
		response, err := parseSshCertData(body)
		if err != nil {
			return response, err
		}

		if !response.Response.Success {
			return response, fmt.Errorf("error getting certificate object, error status: %v, error description: %s", response.Response.ErrorCode, response.Response.ErrorMessage)
		}

		if response.ProcessingDetails.Status == "Rejected" {
			return response, fmt.Errorf("error getting certificate object, error status: %s, error description: %s", response.ProcessingDetails.Status, response.ProcessingDetails.StatusDescription)
		}
		return response, nil
	case http.StatusBadRequest:
		response, err := parseSshCertData(body)
		if err != nil {
			return response, err
		}
		if !response.Response.Success {
			return response, fmt.Errorf("error getting certificate object, error status: %d, error description: %s", response.Response.ErrorCode, response.Response.ErrorMessage)
		}
		return response, nil
	case http.StatusUnauthorized:
		err := NewAuthenticationError(body)
		return retrieveResponse, err
	default:
		return retrieveResponse, fmt.Errorf("unexpected status code. Status: %s", httpStatus)
	}
}

func parseSshCertData(b []byte) (data certificate.TppSshCertOperationResponse, err error) {
	err = json.Unmarshal(b, &data)
	return
}

func convertToGenericRetrieveResponse(data *certificate.TppSshCertOperationResponse) *certificate.SshCertificateObject {

	response := &certificate.SshCertificateObject{}

	response.CertificateDetails = data.CertificateDetails
	response.PrivateKeyData = data.PrivateKeyData
	response.PublicKeyData = data.PublicKeyData
	response.CertificateData = data.CertificateData
	response.Guid = data.Guid
	response.DN = data.DN
	response.CAGuid = data.CAGuid
	response.CADN = data.CADN
	response.ProcessingDetails = data.ProcessingDetails

	return response
}

func getSshConfigUrl(key, value string) string {
	var url string
	query := fmt.Sprintf("%s=%s", key, value)
	query = netUrl.PathEscape(query)
	url = fmt.Sprintf("%s?%s", urlResourceSshCAPubKey, query)
	return url
}

func RetrieveSshConfig(c *Connector, ca *certificate.SshCaTemplateRequest) (*certificate.SshConfig, error) {

	var url string
	if ca.Template != "" {
		fullPath := getSshCaDN(ca.Template)
		url = getSshConfigUrl("DN", fullPath)
		fmt.Println("Retrieving the configured CA public key for template:", fullPath)
	} else if ca.Guid != "" {
		url = getSshConfigUrl("guid", ca.Guid)
		fmt.Println("Retrieving the configured CA public key for template with GUID:", ca.Guid)
	} else {
		return nil, fmt.Errorf("CA template or GUID are not specified")
	}

	statusCode, status, body, err := c.request("GET", urlResource(url), nil)

	if err != nil {
		return nil, err
	}
	conf := certificate.SshConfig{}
	switch statusCode {

	case http.StatusOK, http.StatusAccepted:
		conf.CaPublicKey = string(body)

	default:
		return nil, fmt.Errorf("error while retriving CA public key, error body:%s, status:%s and status code:%v", string(body), status, statusCode)
	}

	if c.accessToken != "" {
		principals, err := RetrieveSshCaPrincipals(c, ca)
		if err != nil {
			return nil, err
		}

		conf.Principals = principals
	} else {
		fmt.Println("Skipping retrieval of Default Principals. No authentication data is provided.")
	}

	return &conf, nil
}

func RetrieveSshCaPrincipals(c *Connector, ca *certificate.SshCaTemplateRequest) ([]string, error) {

	tppReq := certificate.SshTppCaTemplateRequest{}

	if ca.Template != "" {
		tppReq.DN = getSshCaDN(ca.Template)
		fmt.Println("Retrieving the configured Default Principals for template:", tppReq.DN)
	} else if ca.Guid != "" {
		tppReq.Guid = ca.Guid
		fmt.Println("Retrieving the configured Default Principals for template with GUID:", ca.Guid)
	} else {
		return nil, fmt.Errorf("CA template or GUID are not specified")
	}

	statusCode, status, body, err := c.request("POST", urlResourceSshCADetails, tppReq)

	if err != nil {
		return nil, err
	}

	data, err := parseSshCaDetailsRequestResult(statusCode, status, body)

	if err != nil {
		return nil, err
	}

	return data.AccessControl.DefaultPrincipals, nil
}

func parseSshCaDetailsRequestResult(httpStatusCode int, httpStatus string, body []byte) (*certificate.SshTppCaTemplateResponse, error) {
	switch httpStatusCode {
	case http.StatusOK, http.StatusAccepted:
		data, err := parseSshCaDetailsRequestData(body)
		if err != nil {
			return nil, err
		}
		if !data.Response.Success {
			return data, fmt.Errorf("error requesting CA template details, error code: %d, error description: %s", data.Response.ErrorCode, data.Response.ErrorMessage)
		}

		return data, nil

	default:
		data, err := parseSshCaDetailsRequestData(body)
		if err != nil {
			return nil, err
		}
		return data, fmt.Errorf("unexpected status code on TPP CA details Request. Status code: %s, %s", httpStatus, data.Response.ErrorMessage)

	}
}

func parseSshCaDetailsRequestData(b []byte) (data *certificate.SshTppCaTemplateResponse, err error) {
	err = json.Unmarshal(b, &data)
	return
}

func getSshCaDN(ca string) string {

	fullPath := ca
	if !strings.HasPrefix(ca, util.PathSeparator) {
		fullPath = util.PathSeparator + ca
	}

	if !strings.HasPrefix(fullPath, SSHCaRootPath) {
		fullPath = SSHCaRootPath + fullPath
	}

	return fullPath
}
