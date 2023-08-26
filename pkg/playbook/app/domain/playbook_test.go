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

package domain

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi"
	"github.com/stretchr/testify/suite"
)

type PlaybookSuite struct {
	suite.Suite
	testCases           []testCase
	nonWindowsTestCases []testCase
	windowsTestCases    []testCase
}

type testCase struct {
	err  error
	name string
	pb   Playbook
}

func (s *PlaybookSuite) SetupTest() {

	req := PlaybookRequest{
		Zone: "My\\App",
		Subject: Subject{
			CommonName: "foo.bar.venafi.com",
		},
	}

	config := Config{
		Connection: Connection{
			Platform: venafi.TLSPCloud,
			Credentials: Authentication{
				Authentication: endpoint.Authentication{
					APIKey: "foobarGibberish123",
				},
			},
		},
	}

	s.testCases = []testCase{
		{
			err:  ErrNoConfig,
			name: "NoConfig",
			pb: Playbook{
				Config: Config{},
			},
		},
		{
			err:  ErrNoCredentials,
			name: "EmptyCredentials",
			pb: Playbook{
				Config: Config{
					Connection: Connection{
						TrustBundlePath: "asd",
						URL:             "foo",
					},
				},
			},
		},
		{
			err:  ErrMultipleCredentials,
			name: "MultipleCredentials",
			pb: Playbook{
				Config: Config{
					Connection: Connection{
						Credentials: Authentication{
							Authentication: endpoint.Authentication{
								AccessToken: "foobar123",
								APIKey:      "xyz456abc",
							},
						},
					},
				},
			},
		},
		{
			err:  ErrNoTPPURL,
			name: "TPPEmptyURL",
			pb: Playbook{
				Config: Config{
					Connection: Connection{
						Credentials: Authentication{
							Authentication: endpoint.Authentication{
								AccessToken: "someToken",
							},
						},
					},
				},
			},
		},
		{
			err:  ErrTrustBundleNotExist,
			name: "TrustBundleNotExist",
			pb: Playbook{
				Config: Config{
					Connection: Connection{
						Credentials: Authentication{
							Authentication: endpoint.Authentication{
								AccessToken: "someToken",
							},
						},
						URL:             "https://foo.bar.kwan",
						TrustBundlePath: "/foo/bar/bundle.pem",
					},
				},
			},
		},
		{
			err:  ErrNoTasks,
			name: "NoTasks",
			pb: Playbook{
				Config:           config,
				CertificateTasks: nil,
			},
		},
		{
			err:  ErrNoRequestZone,
			name: "NoRequestZone",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					{
						Request: PlaybookRequest{},
					},
				},
			},
		},
		{
			err:  ErrNoRequestCN,
			name: "NoRequestCN",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					{
						Request: PlaybookRequest{
							Zone: "My\\App",
						},
					},
				},
			},
		},

		{
			err:  ErrNoInstallations,
			name: "NoInstallationInTask",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					{
						Request: req,
					},
				},
			},
		},
		{
			err:  ErrUndefinedInstallationFormat,
			name: "InvalidInstallationType",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					{
						Request: req,
						Installations: Installations{
							{
								Type: FormatUnknown,
								File: "something",
							},
						},
					},
				},
			},
		},

		{
			err:  ErrNoInstallationFile,
			name: "NoJKSLocation",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					{
						Request: req,
						Installations: Installations{
							{
								Type: FormatJKS,
							},
						},
					},
				},
			},
		},
		{
			err:  ErrNoJKSAlias,
			name: "NoJKSAlias",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					CertificateTask{
						Name:    "testTask",
						Request: req,
						Installations: Installations{
							Installation{
								Type: FormatJKS,
								File: "somewhere",
							},
						},
					},
				},
			},
		},
		{
			err:  ErrNoJKSPassword,
			name: "NoJKSPassword",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					CertificateTask{
						Name:    "testTask",
						Request: req,
						Installations: Installations{
							Installation{
								Type:     FormatJKS,
								File:     "somewhere",
								JKSAlias: "someAlias",
							},
						},
					},
				},
			},
		},
		{
			err:  ErrJKSPasswordLength,
			name: "JKSPasswordTooShort",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					CertificateTask{
						Name:    "testTask",
						Request: req,
						Installations: Installations{
							Installation{
								Type:        FormatJKS,
								File:        "somewhere",
								JKSAlias:    "alias",
								JKSPassword: "abc12",
							},
						},
					},
				},
			},
		},

		{
			err:  ErrNoInstallationFile,
			name: "NoPEMLocation",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					{
						Request: req,
						Installations: Installations{
							{
								Type: FormatPEM,
							},
						},
					},
				},
			},
		},
		{
			err:  ErrNoChainFile,
			name: "NoPEMChainFile",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					CertificateTask{
						Name:    "testTask",
						Request: req,
						Installations: Installations{
							Installation{
								Type: FormatPEM,
								File: "path/to/cert.cer",
							},
						},
					},
				},
			},
		},
		{
			err:  ErrNoKeyFile,
			name: "NoPEMKeyFile",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					CertificateTask{
						Name:    "testTask",
						Request: req,
						Installations: Installations{
							Installation{
								Type:      FormatPEM,
								File:      "somewhere",
								ChainFile: "chain.pem",
							},
						},
					},
				},
			},
		},

		{
			err:  ErrNoInstallationFile,
			name: "NoPKCS12Location",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					{
						Request: req,
						Installations: Installations{
							{
								Type: FormatPKCS12,
							},
						},
					},
				},
			},
		},

		{
			err:  nil,
			name: "ValidPEMConfig",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					{
						Name:    "testTask",
						Request: req,
						Installations: Installations{
							{
								Type:      FormatPEM,
								File:      "/foo/bar/pem/cer.cer",
								ChainFile: "/foo/bar/pem/chain.pem",
								KeyFile:   "/foo/bar/pem/key.pem",
							},
						},
					},
				},
			},
		},
		{
			err:  nil,
			name: "ValidJKSConfig",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					{
						Name:    "testTask",
						Request: req,
						Installations: Installations{
							{
								Type:        FormatJKS,
								File:        "somewhere",
								JKSAlias:    "alias",
								JKSPassword: "abc123",
							},
						},
					},
				},
			},
		},
		{
			err:  nil,
			name: "ValidPKCS12Config",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					{
						Name:    "testTask",
						Request: req,
						Installations: Installations{
							{
								Type:        FormatPKCS12,
								File:        "somewhere",
								P12Password: "foo123",
							},
						},
					},
				},
			},
		},
	}

	s.nonWindowsTestCases = []testCase{
		{
			err:  ErrNoCAPILocation,
			name: "NoCAPILocation",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					{
						Request: req,
						Installations: Installations{
							{
								Type: FormatCAPI,
							},
						},
					},
				},
			},
		},
		{
			err:  ErrCAPIOnNonWindows,
			name: "CAPIOnNonWindows",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					CertificateTask{
						Name:    "testTask",
						Request: req,
						Installations: Installations{
							Installation{
								Type:     FormatCAPI,
								Location: "somewhere",
							},
						},
					},
				},
			},
		},
	}

	s.windowsTestCases = []testCase{
		{
			err:  ErrNoCAPILocation,
			name: "NoCAPILocation",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					{
						Request: req,
						Installations: Installations{
							{
								Type: FormatCAPI,
							},
						},
					},
				},
			},
		},
		{
			err:  ErrMalformedCAPILocation,
			name: "MalformedCAPILocation",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					CertificateTask{
						Name:    "testTask",
						Request: req,
						Installations: Installations{
							Installation{
								Type:     FormatCAPI,
								Location: "somewhere",
							},
						},
					},
				},
			},
		},
		{
			err:  ErrInvalidCAPILocation,
			name: "InvalidCAPILocation",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					CertificateTask{
						Name:    "testTask",
						Request: req,
						Installations: Installations{
							Installation{
								Type:     FormatCAPI,
								Location: "somewhere\\MY",
							},
						},
					},
				},
			},
		},
		{
			err:  ErrInvalidCAPIStoreName,
			name: "InvalidCAPIStoreName",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					CertificateTask{
						Name:    "testTask",
						Request: req,
						Installations: Installations{
							Installation{
								Type:     FormatCAPI,
								Location: "LocalMachine\\foo",
							},
						},
					},
				},
			},
		},
		{
			err:  nil,
			name: "ValidCAPIConfig",
			pb: Playbook{
				Config: config,
				CertificateTasks: CertificateTasks{
					CertificateTask{
						Name:    "testTask",
						Request: req,
						Installations: Installations{
							Installation{
								Type:     FormatCAPI,
								Location: "LocalMachine\\MY",
							},
						},
					},
				},
			},
		},
	}
}

func TestPlaybook(t *testing.T) {
	suite.Run(t, new(PlaybookSuite))
}

func (s *PlaybookSuite) TestPlaybook_New() {
	pb := NewPlaybook()

	s.Equal(DefaultFilepath, pb.Location)
	s.Empty(pb.CertificateTasks)
}

func (s *PlaybookSuite) TestPlaybook_IsValid() {
	testCases := s.testCases
	if runtime.GOOS == "windows" {
		fmt.Print("Windows environment")
		testCases = append(testCases, s.windowsTestCases...)
	} else {
		fmt.Println("NON-Windows environment")
		testCases = append(testCases, s.nonWindowsTestCases...)
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			_, err := tc.pb.IsValid()
			if tc.err == nil {
				s.Nil(err)
			} else {
				s.Error(err, tc.err.Error())
			}
		})
	}
}
