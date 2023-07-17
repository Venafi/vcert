package parser

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain/certrequest"
)

type WriterSuite struct {
	suite.Suite
	playbook domain.Playbook
}

func (s *WriterSuite) SetupTest() {
	s.playbook = domain.Playbook{
		CertificateTasks: domain.CertificateTasks{
			{
				Name: "testTask",
				Request: certrequest.Request{
					ChainOption: certrequest.ChainOptionRootFirst,
					CsrOrigin:   certrequest.CSRServiceGenerated,
					CustomFields: certrequest.CustomFields{
						{
							Type:  certrequest.CFTypeOrigin,
							Name:  fmt.Sprintf("cf_%s", RandomString(5)),
							Value: RandomString(10),
						},
					},
					KeyCurve:    certrequest.EccP521,
					KeyPassword: "newPassword!",
					KeyType:     certrequest.KeyTypeRSA,
					Subject: certrequest.Subject{
						CommonName:   "foo.bar.123.venafi.com",
						Country:      "US",
						Locality:     "Salt Lake City",
						Organization: "Venafi",
						Province:     "Utah",
					},
					Zone: "Open Source\\vcert",
				},
				Installations: []domain.Installation{
					{
						Type:        domain.TypePEM,
						Location:    "path/to/my/pem/folder",
						AfterAction: "echo Success!",
					},
				},
				RenewBefore: "30d",
			},
		},
		Config: domain.Config{
			Connection: domain.Connection{
				URL:             "https://foo.bar.venafi.com",
				TrustBundlePath: "path/to/my/trustbundle.pem",
				Credentials: domain.Authentication{
					AccessToken:  "123fooBar",
					RefreshToken: "456XyzABc",
				},
			},
		},
		Location: fmt.Sprintf("./write_test_%s.yaml", RandomString(5)),
	}
}

// this function executes after each test case
func (s *WriterSuite) TearDownTest() {
	err := os.Remove(s.playbook.Location)
	s.Nil(err)
}

func TestWriter(t *testing.T) {
	suite.Run(t, new(WriterSuite))
}

func (s *WriterSuite) TestWriter_WritePlaybook() {
	err := WritePlaybook(s.playbook, s.playbook.Location)
	s.Nil(err)

	pb, err := ReadPlaybook(s.playbook.Location)
	s.Nil(err)
	s.NotNil(pb)

	s.Equal(s.playbook.Location, pb.Location)
	s.Equal(s.playbook.Config.Connection.URL, pb.Config.Connection.URL)
	s.Equal(s.playbook.Config.Connection.TrustBundlePath, pb.Config.Connection.TrustBundlePath)
	s.Equal(s.playbook.Config.Connection.Credentials.AccessToken, pb.Config.Connection.Credentials.AccessToken)
	s.Equal(s.playbook.Config.Connection.Credentials.RefreshToken, pb.Config.Connection.Credentials.RefreshToken)

	task := s.playbook.CertificateTasks[0]
	targetTask := pb.CertificateTasks[0]
	s.Equal(task.Name, targetTask.Name)
	s.Equal(task.RenewBefore, targetTask.RenewBefore)

	req := task.Request
	targetReq := targetTask.Request
	s.Equal(req.ChainOption, targetReq.ChainOption)
	s.Equal(req.CsrOrigin, targetReq.CsrOrigin)

	s.Equal(req.CustomFields[0].Type, targetReq.CustomFields[0].Type)
	s.Equal(req.CustomFields[0].Name, targetReq.CustomFields[0].Name)
	s.Equal(req.CustomFields[0].Value, targetReq.CustomFields[0].Value)

	s.Equal(req.KeyCurve, targetReq.KeyCurve)
	s.Equal(req.KeyType, targetReq.KeyType)

	s.Equal(req.KeyPassword, targetReq.KeyPassword)
	s.Equal(req.Zone, targetReq.Zone)
	s.Equal(req.Subject.CommonName, targetReq.Subject.CommonName)
	s.Equal(req.Subject.Country, targetReq.Subject.Country)
	s.Equal(req.Subject.Locality, targetReq.Subject.Locality)
	s.Equal(req.Subject.Organization, targetReq.Subject.Organization)
	s.Equal(req.Subject.Province, targetReq.Subject.Province)

	inst := task.Installations[0]
	targetInst := targetTask.Installations[0]

	s.Equal(inst.Type, targetInst.Type)
	s.Equal(inst.Location, targetInst.Location)
	s.Equal(inst.AfterAction, targetInst.AfterAction)
}
