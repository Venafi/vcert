package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/pkcs12"

	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain"
)

type logLine struct {
	Level   string `json:"L"`
	UnixTS  string `json:"T"`
	Caller  string `json:"C,omitempty"`
	Message string `json:"M"`
}

type PlaybookSuite struct {
	suite.Suite
}

func (s *PlaybookSuite) SetupTest() {
	tlsConfig = tls.Config{}
}

func TestPlaybook(t *testing.T) {
	suite.Run(t, new(PlaybookSuite))
}

func (s *PlaybookSuite) TestPlaybook_SetTLSConfig() {
	p12FileLocation := "../../test-files/playbook/cert.p12"
	p12Password := "newPassword!"

	playbook := domain.Playbook{
		CertificateTasks: domain.CertificateTasks{
			domain.CertificateTask{
				Name:    "p12Auth",
				Request: domain.PlaybookRequest{KeyPassword: p12Password},
				Installations: domain.Installations{
					domain.Installation{
						Location: p12FileLocation,
						Type:     domain.TypePKCS12,
					},
				},
			},
		},
		Config: domain.Config{
			Connection: domain.Connection{
				Platform:    domain.CTypeTPP,
				Credentials: domain.Authentication{PKCS12: "p12Auth"},
			},
		},
	}

	err := setPlaybookTLSConfig(playbook)
	s.NoError(err)

	tlsCfg := http.DefaultTransport.(*http.Transport).TLSClientConfig

	s.Equal(tls.RenegotiateFreelyAsClient, tlsCfg.Renegotiation)
	s.False(tlsCfg.InsecureSkipVerify)

	p12, err := os.ReadFile(p12FileLocation)
	s.NoError(err)

	blocks, err := pkcs12.ToPEM(p12, p12Password)
	s.NoError(err)

	var pemData []byte
	for _, b := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	s.NotEmpty(tlsCfg.Certificates)
	s.Equal(1, len(tlsCfg.Certificates))
	s.Equal(2, len(tlsCfg.Certificates[0].Certificate))
	s.Equal(blocks[0].Bytes, tlsCfg.Certificates[0].Certificate[0])
	s.Equal(blocks[1].Bytes, tlsCfg.Certificates[0].Certificate[1])
	s.NotNil(tlsCfg.RootCAs)

}

func (s *PlaybookSuite) TestPlaybook_SetTLSConfig_noP12Certificate() {
	logName := "./logout.log"

	zc := zap.NewDevelopmentConfig()
	zc.Encoding = "json"
	zc.OutputPaths = []string{logName}
	l, err := zc.Build()
	s.NoError(err)
	zap.ReplaceGlobals(l)

	playbook := domain.Playbook{
		CertificateTasks: domain.CertificateTasks{
			domain.CertificateTask{
				Name:    "p12Auth",
				Request: domain.PlaybookRequest{KeyPassword: "foo123"},
				Installations: domain.Installations{
					domain.Installation{
						Location: "./bad/location.p12",
						Type:     domain.TypePKCS12,
					},
				},
			},
		},
		Config: domain.Config{
			Connection: domain.Connection{
				Platform:    domain.CTypeTPP,
				Credentials: domain.Authentication{PKCS12: "p12Auth"},
				Insecure:    true,
			},
		},
	}

	err = setPlaybookTLSConfig(playbook)
	s.NoError(err)

	tlsCfg := http.DefaultTransport.(*http.Transport).TLSClientConfig

	s.Equal(tls.RenegotiateFreelyAsClient, tlsCfg.Renegotiation)
	s.True(tlsCfg.InsecureSkipVerify)
	s.Empty(tlsCfg.Certificates)
	s.Nil(tlsCfg.RootCAs)

	f, err := os.Open("./logout.log")
	s.NoError(err)

	warningFound := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		data := scanner.Bytes()
		line := logLine{}
		err = json.Unmarshal(data, &line)
		s.NoError(err)

		level, err := zapcore.ParseLevel(line.Level)
		s.NoError(err)

		if level == zapcore.WarnLevel {
			s.Equal("unable to read PKCS#12 file", line.Message)
			warningFound = true
			break
		}
	}
	err = f.Close()
	s.NoError(err)

	err = os.Remove(logName)
	s.NoError(err)

	s.True(warningFound)
}

func (s *PlaybookSuite) TestPlaybook_SetTLSConfig_noCertAuth() {
	playbook := domain.Playbook{
		CertificateTasks: nil,
		Config: domain.Config{
			Connection: domain.Connection{
				Platform:    domain.CTypeVaaS,
				Credentials: domain.Authentication{},
			},
		},
	}

	err := setPlaybookTLSConfig(playbook)
	s.NoError(err)

	tlsCfg := http.DefaultTransport.(*http.Transport).TLSClientConfig

	s.NotEqual(tls.RenegotiateFreelyAsClient, tlsCfg.Renegotiation)
	s.False(tlsCfg.InsecureSkipVerify)
	s.Empty(tlsCfg.Certificates)
	s.Nil(tlsCfg.RootCAs)
}

func (s *PlaybookSuite) TestPlaybook_SetTLSConfig_Insecure() {
	playbook := domain.Playbook{
		CertificateTasks: nil,
		Config: domain.Config{
			Connection: domain.Connection{
				Insecure: true,
			},
		},
	}

	err := setPlaybookTLSConfig(playbook)
	s.NoError(err)

	tlsCfg := http.DefaultTransport.(*http.Transport).TLSClientConfig
	s.True(tlsCfg.InsecureSkipVerify)
}
