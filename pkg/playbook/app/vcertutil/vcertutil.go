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

package vcertutil

import (
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"time"

	"github.com/Venafi/vcert/v5"
	"go.uber.org/zap"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/venafi/tpp"
)

// EnrollCertificate takes a Request object and requests a certificate to the Venafi platform defined by config.
//
// Then it retrieves the certificate and returns it along with the certificate chain and the private key used.
func EnrollCertificate(config domain.Config, request domain.PlaybookRequest) (*certificate.PEMCollection, *certificate.Request, error) {
	client, err := buildClient(config, request.Zone)
	if err != nil {
		return nil, nil, err
	}

	vRequest := buildRequest(request)

	zoneCfg, err := client.ReadZoneConfiguration()
	if err != nil {
		return nil, nil, err
	}
	zap.L().Debug("successfully read zone config", zap.String("zone", request.Zone))

	err = client.GenerateRequest(zoneCfg, &vRequest)
	if err != nil {
		return nil, nil, err
	}
	zap.L().Debug("successfully updated Request with zone config values")

	var pcc *certificate.PEMCollection

	if client.SupportSynchronousRequestCertificate() {
		pcc, err = client.SynchronousRequestCertificate(&vRequest)
	} else {
		reqID, err := client.RequestCertificate(&vRequest)
		if err != nil {
			return nil, nil, err
		}
		zap.L().Debug("successfully requested certificate", zap.String("requestID", reqID))

		vRequest.PickupID = reqID
		vRequest.Timeout = 180 * time.Second

		pcc, err = client.RetrieveCertificate(&vRequest)
	}

	if err != nil {
		return nil, nil, err
	}
	zap.L().Debug("successfully retrieved certificate", zap.String("certificate", request.Subject.CommonName))

	return pcc, &vRequest, nil
}

func buildClient(config domain.Config, zone string) (endpoint.Connector, error) {
	vConfig := &vcert.Config{
		ConnectorType: config.Connection.GetConnectorType(),
		BaseUrl:       config.Connection.URL,
		Zone:          zone,
		Credentials: &endpoint.Authentication{
			APIKey:       config.Connection.Credentials.APIKey,
			Scope:        config.Connection.Credentials.Scope,
			ClientId:     config.Connection.Credentials.ClientId,
			AccessToken:  config.Connection.Credentials.AccessToken,
			ClientSecret: config.Connection.Credentials.ClientSecret,
		},
		ConnectionTrust: loadTrustBundle(config.Connection.TrustBundlePath),
		LogVerbose:      false,
	}

	if config.Connection.Credentials.IdentityProvider != nil {
		vConfig.Credentials.IdentityProvider = config.Connection.Credentials.IdentityProvider
	}

	client, err := vcert.NewClient(vConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func buildRequest(request domain.PlaybookRequest) certificate.Request {

	vcertRequest := certificate.Request{
		CADN: request.CADN,
		Subject: pkix.Name{
			CommonName:         request.Subject.CommonName,
			Country:            []string{request.Subject.Country},
			Organization:       []string{request.Subject.Organization},
			OrganizationalUnit: request.Subject.OrgUnits,
			Locality:           []string{request.Subject.Locality},
			Province:           []string{request.Subject.Province},
		},
		DNSNames:       request.DNSNames,
		OmitSANs:       request.OmitSANs,
		EmailAddresses: request.EmailAddresses,
		IPAddresses:    getIPAddresses(request.IPAddresses),
		URIs:           getURIs(request.URIs),
		UPNs:           request.UPNs,
		FriendlyName:   request.FriendlyName,
		ChainOption:    request.ChainOption,
		KeyPassword:    request.KeyPassword,
		CustomFields:   request.CustomFields,
	}

	// Set timeout for cert retrieval
	setTimeout(request, &vcertRequest)
	//Set Location
	setLocationWorkload(request, &vcertRequest)
	//Set KeyType
	setKeyType(request, &vcertRequest)
	//Set Origin
	setOrigin(request, &vcertRequest)
	//Set Validity
	setValidity(request, &vcertRequest)
	//Set CSR
	setCSR(request, &vcertRequest)

	return vcertRequest
}

// DecryptPrivateKey takes an encrypted private key and decrypts it using the given password.
//
// The private key must be in PKCS8 format.
func DecryptPrivateKey(privateKey string, password string) (string, error) {
	privateKey, err := util.DecryptPkcs8PrivateKey(privateKey, password)
	return privateKey, err
}

// EncryptPrivateKeyPKCS1 takes a decrypted PKCS8 private key and encrypts it back in PKCS1 format
func EncryptPrivateKeyPKCS1(privateKey string, password string) (string, error) {
	privateKey, err := util.EncryptPkcs1PrivateKey(privateKey, password)
	return privateKey, err
}

// IsValidAccessToken checks that the accessToken in config is not expired.
func IsValidAccessToken(config domain.Config) (bool, error) {
	// No access token provided. Use refresh token to get new access token right away
	if config.Connection.Credentials.AccessToken == "" {
		return false, fmt.Errorf("an access token was not provided for connection to TPP")
	}

	vConfig := &vcert.Config{
		ConnectorType: config.Connection.GetConnectorType(),
		BaseUrl:       config.Connection.URL,
		Credentials: &endpoint.Authentication{
			Scope:       config.Connection.Credentials.Scope,
			ClientId:    config.Connection.Credentials.ClientId,
			AccessToken: config.Connection.Credentials.AccessToken,
		},
		ConnectionTrust: loadTrustBundle(config.Connection.TrustBundlePath),
		LogVerbose:      false,
	}

	client, err := vcert.NewClient(vConfig, false)
	if err != nil {
		return false, err
	}

	_, err = client.(*tpp.Connector).VerifyAccessToken(vConfig.Credentials)

	return err == nil, err
}

// RefreshTPPTokens uses the refreshToken in config to request a new pair of tokens
func RefreshTPPTokens(config domain.Config) (string, string, error) {
	vConfig := &vcert.Config{
		ConnectorType: config.Connection.GetConnectorType(),
		BaseUrl:       config.Connection.URL,
		Credentials: &endpoint.Authentication{
			Scope:    config.Connection.Credentials.Scope,
			ClientId: config.Connection.Credentials.ClientId,
		},
		ConnectionTrust: loadTrustBundle(config.Connection.TrustBundlePath),
		LogVerbose:      false,
	}

	//Creating an empty client
	client, err := vcert.NewClient(vConfig, false)
	if err != nil {
		return "", "", err
	}

	auth := endpoint.Authentication{
		RefreshToken: config.Connection.Credentials.RefreshToken,
		ClientPKCS12: config.Connection.Credentials.P12Task != "",
		Scope:        config.Connection.Credentials.Scope,
		ClientId:     config.Connection.Credentials.ClientId,
	}

	if auth.RefreshToken != "" {
		resp, err := client.(*tpp.Connector).RefreshAccessToken(&auth)
		if err != nil {
			if auth.ClientPKCS12 {
				resp, err2 := client.(*tpp.Connector).GetRefreshToken(&auth)
				if err2 != nil {
					return "", "", errors.Join(err2, err)
				}
				return resp.Access_token, resp.Refresh_token, nil
			}
			return "", "", err
		}
		return resp.Access_token, resp.Refresh_token, nil
	} else if auth.ClientPKCS12 {
		auth.RefreshToken = ""
		resp, err := client.(*tpp.Connector).GetRefreshToken(&auth)
		if err != nil {
			return "", "", err
		}
		return resp.Access_token, resp.Refresh_token, nil
	}

	return "", "", fmt.Errorf("no refresh token or certificate available to refresh access token")
}
