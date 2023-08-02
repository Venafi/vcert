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

package parser

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/playbook/app/domain"
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
				Request: domain.PlaybookRequest{
					ChainOption: certificate.ChainOptionRootFirst,
					CsrOrigin:   certificate.StrServiceGeneratedCSR,
					CustomFields: []certificate.CustomField{
						{
							Name:  fmt.Sprintf("cf_%s", RandomString(5)),
							Value: RandomString(10),
						},
					},
					KeyCurve:    certificate.EllipticCurveP521,
					KeyPassword: "newPassword!",
					KeyType:     certificate.KeyTypeRSA,
					Subject: domain.Subject{
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
						Type:        domain.FormatPEM,
						File:        "path/to/my/pem/folder",
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
	err := WritePlaybook(s.playbook, "C:/foo/bar.yaml")
	s.Error(err)

	err = WritePlaybook(s.playbook, s.playbook.Location)
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
	s.Equal(inst.File, targetInst.File)
	s.Equal(inst.AfterAction, targetInst.AfterAction)
}
