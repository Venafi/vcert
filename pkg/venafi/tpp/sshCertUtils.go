package tpp

import (
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/policy"
	"net/http"
	"strings"
	"time"
)

const (
	CaRootPath = policy.PathSeparator + "VED" + policy.PathSeparator + "Certificate Authority" + policy.PathSeparator + "SSH" + policy.PathSeparator + "Templates"
)

func RequestSSHCertificate(c *Connector, req *certificate.SshCertRequest) (requestID string, err error) {

	sshCertReq := convertToSShCertReq(req)

	fmt.Println("Requesting certificate with key id: ", sshCertReq.KeyId)

	_, _, body, err := c.request("POST", urlResourceSshCertReq, sshCertReq)
	if err != nil {
		return "", err
	}
	var response certificate.TppSshCertRequestResponse
	err = json.Unmarshal(body, &response)

	if err != nil {
		return "", err
	}

	return response.DN, nil
}

func convertToSShCertReq(req *certificate.SshCertRequest) certificate.TPPSshCertRequest {

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

	if req.DestinationAddress != "" {
		tppSshCertReq.ObjectName = req.DestinationAddress
	}
	if req.KeyId != "" {
		tppSshCertReq.KeyId = req.KeyId
	}

	if req.ValidityPeriod != "" {
		tppSshCertReq.ValidityPeriod = req.ValidityPeriod
	}

	if req.SourceAddresses != "" {
		tppSshCertReq.SourceAddresses = req.SourceAddresses
	}

	if req.PublicKeyData != "" {
		tppSshCertReq.PublicKeyData = req.PublicKeyData
	}

	if req.CADN != "" {

		tppSshCertReq.CADN = req.CADN

		if !strings.HasPrefix(tppSshCertReq.CADN, policy.PathSeparator) {
			tppSshCertReq.CADN = policy.PathSeparator + tppSshCertReq.CADN
		}

		if !strings.HasPrefix(tppSshCertReq.CADN, CaRootPath) {
			tppSshCertReq.CADN = CaRootPath + tppSshCertReq.CADN
		}
	}

	if req.ForceCommand != "" {
		tppSshCertReq.ForceCommand = req.ForceCommand
	}

	return tppSshCertReq
}

func RetrieveSSHCertificate(c *Connector, req *certificate.SshCertRequest) (*certificate.TppSshCertRetrieveResponse, error) {
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
		var retrieveResponse *certificate.TppSshCertRetrieveResponse
		retrieveResponse, err := retrieveSshCerOnce(reqRetrieve, c)
		if err != nil {
			return nil, err
		}
		if retrieveResponse.CertificateData != "" {
			return retrieveResponse, nil
		}
		if req.Timeout == 0 {
			return nil, endpoint.ErrCertificatePending{CertificateID: req.PickupID, Status: retrieveResponse.Status}
		}
		if time.Now().After(startTime.Add(req.Timeout)) {
			return nil, endpoint.ErrRetrieveCertificateTimeout{CertificateID: req.PickupID}
		}
		time.Sleep(2 * time.Second)
	}
}

func retrieveSshCerOnce(sshRetrieveReq certificate.TppSshCertRetrieveRequest, c *Connector) (*certificate.TppSshCertRetrieveResponse, error) {
	statusCode, status, body, err := c.request("POST", urlResourceSshCertRet, sshRetrieveReq)
	if err != nil {
		return nil, err
	}
	retrieveResponse, err := parseSshCertRetrieveResult(statusCode, status, body)
	if err != nil {
		return nil, err
	}
	return &retrieveResponse, nil
}

func parseSshCertRetrieveResult(httpStatusCode int, httpStatus string, body []byte) (certificate.TppSshCertRetrieveResponse, error) {
	var retrieveResponse certificate.TppSshCertRetrieveResponse
	switch httpStatusCode {
	case http.StatusOK, http.StatusAccepted:
		retrieveResponse, err := parseSshCertRetrieveData(body)
		if err != nil {
			return retrieveResponse, err
		}
		if !retrieveResponse.Response.Success {
			return retrieveResponse, fmt.Errorf("error getting certificate, error code: %d, error description: %s", retrieveResponse.Response.ErrorCode, retrieveResponse.Response.ErrorMessage)
		}
		return retrieveResponse, nil
	default:
		return retrieveResponse, fmt.Errorf("Unexpected status code on TPP SSH Certificate Retrieval. Status: %s", httpStatus)
	}
}

func parseSshCertRetrieveData(b []byte) (data certificate.TppSshCertRetrieveResponse, err error) {
	err = json.Unmarshal(b, &data)
	return
}
