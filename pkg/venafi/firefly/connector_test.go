/*
 * Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
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
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type ConnectorSuite struct {
	suite.Suite
	idpServer     *IdentityProviderMockServer
	fireflyServer *FireflyMockServer
}

func (s *ConnectorSuite) SetupSuite() {
	//setting the tls connection as insecure for testing purposes
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	fmt.Println("mocking servers")
	s.idpServer = newIdentityProviderMockServer()
	s.fireflyServer = newFireflyMockServer()
}

func (s *ConnectorSuite) TearDownSuite() {
	fmt.Println("closing mocked servers")
	s.idpServer.server.Close()
	s.fireflyServer.server.Close()
}

func (s *ConnectorSuite) createCredFlowAuth() *endpoint.Authentication {
	return &endpoint.Authentication{
		Scope:        TestingScope,
		ClientId:     TestingClientID,
		ClientSecret: TestingClientSecret,
		IdentityProvider: &endpoint.OAuthProvider{
			TokenURL: s.idpServer.idpURL + s.idpServer.tokenPath,
			Audience: TestingAudience,
		},
	}
}

func (s *ConnectorSuite) createPasswordFlowAuth() *endpoint.Authentication {
	return &endpoint.Authentication{
		User:     TestingUserName,
		Password: TestingUserPassword,
		Scope:    TestingScope,
		ClientId: TestingClientID,
		IdentityProvider: &endpoint.OAuthProvider{
			TokenURL: s.idpServer.idpURL + s.idpServer.tokenPath,
			Audience: TestingAudience,
		},
	}
}

func (s *ConnectorSuite) createDevFlowAuth() *endpoint.Authentication {
	return &endpoint.Authentication{
		Scope:    TestingScope,
		ClientId: TestingClientID,
		IdentityProvider: &endpoint.OAuthProvider{
			DeviceURL: s.idpServer.idpURL + s.idpServer.devicePath,
			TokenURL:  s.idpServer.idpURL + s.idpServer.tokenPath,
			Audience:  TestingAudience,
		},
	}
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run
func TestConnectorSuite(t *testing.T) {
	suite.Run(t, new(ConnectorSuite))
}

func (s *ConnectorSuite) TestNewConnector() {

	s.Run("Success", func() {
		fireflyConnector, err := NewConnector("my.firefly:8080", "", false, nil)

		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), fireflyConnector)
		assert.Equal(s.T(), "https://my.firefly:8080/", fireflyConnector.baseURL)
	})
}

func (s *ConnectorSuite) TestGetType() {
	fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating CyberArk Workload Identity Manager connector: %w", err).Error())
	assert.Equal(s.T(), endpoint.ConnectorTypeFirefly, fireflyConnector.GetType())
}

func (s *ConnectorSuite) TestAuthenticate() {
	s.Run("AuthenticationConfNotProvided", func() {
		fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, "", false, nil)
		assert.Nil(s.T(), err, fmt.Errorf("error creating CyberArk Workload Identity Manager connector: %w", err).Error())

		err = fireflyConnector.Authenticate(nil)

		if assert.Errorf(s.T(), err, "expected to get an error but was gotten the access_token") {
			assert.Equal(s.T(), "failed to authenticate: no credentials provided", err.Error())
		}
		assert.Equal(s.T(), "", fireflyConnector.accessToken)
	})

	s.Run("Success", func() {
		fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, "", false, nil)
		assert.Nil(s.T(), err, fmt.Errorf("error creating CyberArk Workload Identity Manager connector: %w", err).Error())

		err = fireflyConnector.Authenticate(s.createCredFlowAuth())

		assert.Nil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
		assert.NotNil(s.T(), fireflyConnector.accessToken)
	})
}

func (s *ConnectorSuite) TestClientCredentialFlow() {
	fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating CyberArk Workload Identity Manager connector: %w", err).Error())

	oauthToken, err := fireflyConnector.Authorize(s.createCredFlowAuth())

	assert.Nil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
	assert.NotNil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestClientCredentialFlow_Unauthorized() {
	fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating CyberArk Workload Identity Manager connector: %w", err).Error())

	auth := s.createCredFlowAuth()
	//changing the clientId
	auth.ClientId = "unauthorized"

	oauthToken, err := fireflyConnector.Authorize(auth)

	assert.NotNil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
	assert.Nil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestClientPasswordFlow() {
	fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating CyberArk Workload Identity Manager connector: %w", err).Error())

	oauthToken, err := fireflyConnector.Authorize(s.createPasswordFlowAuth())

	assert.Nil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
	assert.NotNil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestClientPasswordFlow_Unauthorized() {
	fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating CyberArk Workload Identity Manager connector: %w", err).Error())

	auth := s.createPasswordFlowAuth()
	auth.ClientId = "unauthorized"

	oauthToken, err := fireflyConnector.Authorize(auth)

	assert.NotNil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
	assert.Nil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestDeviceFlow() {
	fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating CyberArk Workload Identity Manager connector: %w", err).Error())

	oauthToken, err := fireflyConnector.Authorize(s.createDevFlowAuth())

	assert.Nil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
	assert.NotNil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestDeviceFlow_AuthPending() {
	fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating CyberArk Workload Identity Manager connector: %w", err).Error())

	auth := s.createDevFlowAuth()
	auth.ClientId = TestingClientIDAuthPending

	oauthToken, err := fireflyConnector.Authorize(auth)

	assert.Nil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
	assert.NotNil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestDeviceFlow_SlowDown() {
	fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating CyberArk Workload Identity Manager connector: %w", err).Error())

	auth := s.createDevFlowAuth()
	auth.ClientId = TestingClientIDSlowDown

	oauthToken, err := fireflyConnector.Authorize(auth)

	assert.Nil(s.T(), err, fmt.Errorf("error getting acccess token: %w", err).Error())
	assert.NotNil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestDeviceFlow_AccessDenied() {
	fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating CyberArk Workload Identity Manager connector: %w", err).Error())

	auth := s.createDevFlowAuth()
	auth.ClientId = TestingClientIDAccessDenied

	oauthToken, err := fireflyConnector.Authorize(auth)

	if assert.Errorf(s.T(), err, "expected to get an error but was gotten the access_token") {
		assert.Equal(s.T(), "vcert error: your data contains problems: auth error: the access from device was denied by the user", err.Error())
	}
	assert.Nil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestDeviceFlow_ExpiredToken() {
	fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, "", false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating CyberArk Workload Identity Manager connector: %w", err).Error())

	auth := s.createDevFlowAuth()
	auth.ClientId = TestingClientIDExpiredToken

	oauthToken, err := fireflyConnector.Authorize(auth)

	if assert.Errorf(s.T(), err, "expected to get an error but was gotten the access_token") {
		assert.Equal(s.T(), "vcert error: your data contains problems: auth error: the device code expired", err.Error())
	}
	assert.Nil(s.T(), oauthToken)
}

func (s *ConnectorSuite) TestSynchronousRequestCertificate_CSR_Service_Generated() {
	fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, TestingPolicyName, false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating CyberArk Workload Identity Manager connector: %w", err).Error())

	//connector authenticating
	err = fireflyConnector.Authenticate(s.createDevFlowAuth())

	assert.Nil(s.T(), err, fmt.Errorf("error getting access token: %w", err).Error())
	assert.NotNil(s.T(), fireflyConnector.accessToken)

	//creating the CertRequest
	request := certificate.Request{
		Subject: pkix.Name{
			Country:      []string{"MX"},
			Organization: []string{"Venafi"},
			Locality:     []string{"Merida"},
			Province:     []string{"Yucatan"},
			CommonName:   "vcert.test.vfidev.com",
		},
		KeyType:        certificate.KeyTypeRSA,
		KeyLength:      certificate.DefaultRSAlength,
		ValidityPeriod: "P90D",
	}
	s.Run("Success", func() {
		pemCollection, err := fireflyConnector.SynchronousRequestCertificate(&request)

		assert.Nil(s.T(), err, fmt.Errorf("error requesting the certificate: %w", err).Error())
		assert.NotNil(s.T(), pemCollection)
	})
	s.Run("Failure_rsa_size_not_supported", func() {
		//copying the request to keep the original without changes
		requestRSASize1024 := request
		requestRSASize1024.KeyLength = 1024

		pemCollection, err := fireflyConnector.SynchronousRequestCertificate(&requestRSASize1024)

		if assert.Errorf(s.T(), err, "expected to get an error but was gotten the certificate") {
			assert.ErrorContains(s.T(), err, "key size 1024 is not supported. Valid RSA sizes for CyberArk Workload Identity Manager are ")
		}
		assert.Nil(s.T(), pemCollection)
	})
	s.Run("Failure_request", func() {
		//setting momentarily to work in secure mode to get an error managed by the request method
		http.DefaultTransport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = false
		pemCollection, err := fireflyConnector.SynchronousRequestCertificate(&request)
		//putting back to insecure mode
		http.DefaultTransport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true

		if assert.Errorf(s.T(), err, "expected to get an error but was gotten the certificate") {
			assert.ErrorContains(s.T(), err, "tls: failed to verify certificate: x509: certificate signed by unknown authority")
		}
		assert.Nil(s.T(), pemCollection)
	})
	s.Run("Failure_wrong_request", func() {
		//copying the request to keep the original without changes
		requestWithoutSubject := request
		requestWithoutSubject.Subject = pkix.Name{}

		pemCollection, err := fireflyConnector.SynchronousRequestCertificate(&requestWithoutSubject)

		if assert.Errorf(s.T(), err, "expected to get an error but was gotten the certificate") {
			assert.ErrorContains(s.T(), err, "unexpected status code on CyberArk Workload Identity Manager. Status: ")
		}
		assert.Nil(s.T(), pemCollection)
	})
	s.Run("Failure_corrupted_cert_received", func() {
		//copying the connector to keep the original without changes
		fireflyConnectorFailingPolicy := fireflyConnector
		fireflyConnectorFailingPolicy.zone = TestingFailingPolicyName
		pemCollection, err := fireflyConnectorFailingPolicy.SynchronousRequestCertificate(&request)

		if assert.Errorf(s.T(), err, "expected to get an error but was gotten the certificate") {
			assert.ErrorContains(s.T(), err, "x509: malformed certificate")
		}
		assert.Nil(s.T(), pemCollection)
	})
}

func (s *ConnectorSuite) TestSynchronousRequestCertificate_CSR_Provided() {
	fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, TestingPolicyName, false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating CyberArk Workload Identity Manager connector: %w", err).Error())

	//connector authenticating
	err = fireflyConnector.Authenticate(s.createDevFlowAuth())

	assert.Nil(s.T(), err, fmt.Errorf("error getting access token: %w", err).Error())
	assert.NotNil(s.T(), fireflyConnector.accessToken)

	//creating the CertRequest
	request := certificate.Request{
		CsrOrigin: certificate.UserProvidedCSR,
	}
	request.SetCSR([]byte(csr_test))

	s.Run("Success", func() {
		pemCollection, err := fireflyConnector.SynchronousRequestCertificate(&request)

		assert.Nil(s.T(), err, fmt.Errorf("error requesting the certificate: %w", err).Error())
		assert.NotNil(s.T(), pemCollection)
	})
	s.Run("Failure_request", func() {
		//setting momentarily to work in secure mode to get an error managed by the request method
		http.DefaultTransport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = false
		pemCollection, err := fireflyConnector.SynchronousRequestCertificate(&request)
		//putting back to insecure mode
		http.DefaultTransport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true

		if assert.Errorf(s.T(), err, "expected to get an error but was gotten the certificate") {
			assert.ErrorContains(s.T(), err, "tls: failed to verify certificate: x509: certificate signed by unknown authority")
		}
		assert.Nil(s.T(), pemCollection)
	})
	s.Run("Failure_wrong_request", func() {
		//copying the request to keep the original without changes
		requestWithoutSubject := certificate.Request{}

		pemCollection, err := fireflyConnector.SynchronousRequestCertificate(&requestWithoutSubject)

		if assert.Errorf(s.T(), err, "expected to get an error but was gotten the certificate") {
			assert.ErrorContains(s.T(), err, "unexpected status code on CyberArk Workload Identity Manager. Status: ")
		}
		assert.Nil(s.T(), pemCollection)
	})
	s.Run("Failure_corrupted_cert_received", func() {
		//copying the connector to keep the original without changes
		fireflyConnectorFailingPolicy := fireflyConnector
		fireflyConnectorFailingPolicy.zone = TestingFailingPolicyName
		pemCollection, err := fireflyConnectorFailingPolicy.SynchronousRequestCertificate(&request)

		if assert.Errorf(s.T(), err, "expected to get an error but was gotten the certificate") {
			assert.ErrorContains(s.T(), err, "x509: malformed certificate")
		}
		assert.Nil(s.T(), pemCollection)
	})
}

func (s *ConnectorSuite) TestGetCertificateRequestUrl() {
	fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, TestingPolicyName, false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating firefly connector: %w", err).Error())
	s.Run("CertificateSigningRequestURL", func() {
		urlRes := fireflyConnector.getCertificateRequestUrl(&certificate.Request{CsrOrigin: certificate.UserProvidedCSR})
		assert.Equal(s.T(), urlResourceCertificateRequestCSR, urlRes)
	})
	s.Run("CertificateRequestURL", func() {
		urlRes := fireflyConnector.getCertificateRequestUrl(&certificate.Request{CsrOrigin: certificate.ServiceGeneratedCSR})
		assert.Equal(s.T(), urlResourceCertificateRequest, urlRes)
	})
	s.Run("DefaultCertificateRequestURL", func() {
		urlRes := fireflyConnector.getCertificateRequestUrl(&certificate.Request{})
		assert.Equal(s.T(), urlResourceCertificateRequest, urlRes)
	})
}

func (s *ConnectorSuite) TestSupportSynchronousRequestCertificate() {
	fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, TestingPolicyName, false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating firefly connector: %w", err).Error())
	assert.True(s.T(), fireflyConnector.SupportSynchronousRequestCertificate())
}

func (s *ConnectorSuite) TestGetCertificateRequest() {
	fireflyConnector, err := NewConnector(s.fireflyServer.serverURL, TestingPolicyName, false, nil)
	assert.Nil(s.T(), err, fmt.Errorf("error creating firefly connector: %w", err).Error())

	s.Run("Success", func() {
		exampleUrl, err := url.Parse("spiffe://rest.example.com")

		//creating the CertRequest
		request := certificate.Request{
			Subject: pkix.Name{
				CommonName:         "vcert.test.vfidev.com",
				Organization:       []string{"Venafi"},
				OrganizationalUnit: []string{"Platform Engineering"},
				Locality:           []string{"Merida"},
				Province:           []string{"Yucatan"},
				Country:            []string{"MX"},
			},
			DNSNames:       []string{"vcert.test.vfidev.com"},
			IPAddresses:    []net.IP{[]byte("10.20.30.40")},
			EmailAddresses: []string{"venafi.dev@example.com"},
			URIs:           []*url.URL{exampleUrl},
			KeyType:        certificate.KeyTypeRSA,
			KeyLength:      certificate.DefaultRSAlength,
			ValidityPeriod: "P90D",
		}

		certReq, err := fireflyConnector.getCertificateRequest(&request)
		assert.Nil(s.T(), err, fmt.Errorf("expected error nil but was gotten an error: %w", err).Error())
		assert.NotNil(s.T(), certReq)

		assert.Equal(s.T(), TestingPolicyName, certReq.PolicyName)
		//validating the subject
		assert.Equal(s.T(), request.Subject.CommonName, certReq.Subject.CommonName)
		assert.Equal(s.T(), request.Subject.Organization[0], certReq.Subject.Organization)
		assert.Equal(s.T(), request.Subject.OrganizationalUnit[0], certReq.Subject.OrgUnits[0])
		assert.Equal(s.T(), request.Subject.Locality[0], certReq.Subject.Locality)
		assert.Equal(s.T(), request.Subject.Province[0], certReq.Subject.State)
		assert.Equal(s.T(), request.Subject.Country[0], certReq.Subject.Country)

		//validating the AltNames
		assert.Equal(s.T(), request.DNSNames, certReq.AlternativeName.DnsNames)
		assert.Equal(s.T(), request.IPAddresses[0].String(), certReq.AlternativeName.IpAddresses[0])
		assert.Equal(s.T(), request.EmailAddresses, certReq.AlternativeName.EmailAddresses)
		assert.Equal(s.T(), request.URIs[0].String(), certReq.AlternativeName.Uris[0])

		//validating KeyAlgorithm
		assert.Equal(s.T(), request.KeyType.String()+"_"+strconv.Itoa(request.KeyLength), certReq.KeyAlgorithm)
		//validating ValidityPeriod
		assert.Equal(s.T(), request.ValidityPeriod, *certReq.ValidityPeriod)
	})
	s.Run("Invalid_RSA_Size", func() {
		//creating the CertRequest
		request := certificate.Request{
			KeyType:   certificate.KeyTypeRSA,
			KeyLength: 1024,
		}

		certReq, err := fireflyConnector.getCertificateRequest(&request)
		if assert.Errorf(s.T(), err, "expected to get an error but was gotten the certificate") {
			assert.ErrorContains(s.T(), err, "key size 1024 is not supported. Valid RSA sizes for Firefly are ")
		}
		assert.Nil(s.T(), certReq)

	})
	s.Run("EllipticCurve_not_set", func() {
		//creating the CertRequest
		request := certificate.Request{
			KeyType: certificate.KeyTypeECDSA,
		}

		certReq, err := fireflyConnector.getCertificateRequest(&request)
		assert.Nil(s.T(), err, fmt.Errorf("expected error nil but was gotten an error: %w", err).Error())
		assert.NotNil(s.T(), certReq)
		//validating KeyAlgorithm
		curveDefault := certificate.EllipticCurveDefault
		assert.Equal(s.T(), "EC_"+curveDefault.String(), certReq.KeyAlgorithm)
	})
	s.Run("UserProvidedCSR", func() {
		//creating the CertRequest
		request := certificate.Request{
			CsrOrigin: certificate.UserProvidedCSR,
		}
		request.SetCSR([]byte(csr_test))

		certReq, err := fireflyConnector.getCertificateRequest(&request)
		assert.Nil(s.T(), err, fmt.Errorf("expected error nil but was gotten an error: %w", err).Error())
		assert.NotNil(s.T(), certReq)
		//validating CSR was set
		assert.Equal(s.T(), csr_test, certReq.CSR)
	})
}
