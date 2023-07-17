package service

import (
	"os"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain/certrequest"
)

type ServiceSuite struct {
	suite.Suite
	testCases []struct {
		name   string
		config domain.Config
		task   domain.CertificateTask
	}
	errTestCases []struct {
		name   string
		config domain.Config
		task   domain.CertificateTask
		err    error
	}
}

func (s *ServiceSuite) SetupTest() {

	request := certrequest.Request{
		CADN:            "",
		ChainOption:     certrequest.ChainOptionRootLast,
		CsrOrigin:       certrequest.CSRServiceGenerated,
		CustomFields:    nil,
		DNSNames:        nil,
		EmailAddresses:  nil,
		FetchPrivateKey: false,
		FriendlyName:    "",
		IPAddresses:     nil,
		IssuerHint:      "",
		KeyCurve:        certrequest.EccUnknown,
		KeyLength:       2048,
		KeyPassword:     "foobar123",
		KeyType:         certrequest.KeyTypeRSA,
		Location:        certrequest.Location{},
		OmitSANs:        false,
		Origin:          "",
		Subject: certrequest.Subject{
			CommonName:   "foo.bar.rvela.com",
			Country:      "US",
			Locality:     "Salt Lake City",
			Organization: "Venafi",
			OrgUnits:     nil,
			Province:     "Utah",
		},
		UPNs:      nil,
		URIs:      nil,
		ValidDays: "",
		Zone:      "",
	}

	s.testCases = []struct {
		name   string
		config domain.Config
		task   domain.CertificateTask
	}{
		{
			name:   "PEM",
			config: domain.Config{ForceRenew: true},
			task: domain.CertificateTask{
				Name:    "testcertpem",
				Request: request,
				Installations: domain.Installations{
					{
						Type:             domain.TypePEM,
						Location:         "./pem",
						AfterAction:      "echo Success!",
						PEMCertFilename:  "cert.cert",
						PEMChainFilename: "cert.chain",
						PEMKeyFilename:   "pk.pem",
					},
				},
				RenewBefore: "30d",
			},
		},
		{
			name:   "JKS",
			config: domain.Config{},
			task: domain.CertificateTask{
				Name:    "testcertjks",
				Request: request,
				Installations: domain.Installations{
					{
						Type:        domain.TypeJKS,
						Location:    "./jks/testjks.jks",
						AfterAction: "",
					},
				},
				RenewBefore: "30d",
			},
		},
		{
			name:   "PKCS12",
			config: domain.Config{},
			task: domain.CertificateTask{
				Name:    "testcertp12",
				Request: request,
				Installations: domain.Installations{
					{
						Type:        domain.TypePKCS12,
						Location:    "./pkcs12/testp12.p12",
						AfterAction: "",
					},
				},
				RenewBefore: "30d",
			},
		},
		{
			name:   "Multicert",
			config: domain.Config{},
			task: domain.CertificateTask{
				Name:    "testmulticert",
				Request: request,
				Installations: domain.Installations{
					{
						Type:        domain.TypePKCS12,
						Location:    "./pkcs12/testp12.p12",
						AfterAction: "",
					},
					{
						Type:        domain.TypeJKS,
						Location:    "./jks/testjks.jks",
						AfterAction: "",
					},
				},
				RenewBefore: "30d",
			},
		},
	}
}

func TestService(t *testing.T) {
	suite.Run(t, new(ServiceSuite))
}

func (s *ServiceSuite) TestService_ValidateCredentials() {

}

func (s *ServiceSuite) TestService_Execute() {
	for _, tc := range s.testCases {
		s.Run(tc.name, func() {
			err := Execute(tc.config, tc.task)
			s.Empty(err)
		})
	}
}

func (s *ServiceSuite) TestService_ExecuteErrors() {
	for _, tc := range s.errTestCases {
		s.Run(tc.name, func() {
			err := Execute(tc.config, tc.task)
			s.Empty(err)
		})
	}
}

// this function executes after each test case
func (s *ServiceSuite) TearDownTest() {
	err := os.RemoveAll("./jks")
	s.Nil(err)
	err = os.RemoveAll("./pem")
	s.Nil(err)
	err = os.RemoveAll("./pkcs12")
	s.Nil(err)
}
