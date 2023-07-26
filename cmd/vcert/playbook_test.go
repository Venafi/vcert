package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"testing"

	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/pkcs12"
)

type logLine struct {
	Level   string `json:"L"`
	UnixTS  string `json:"T"`
	Caller  string `json:"C,omitempty"`
	Message string `json:"M"`
}

func TestSetPlaybookTLSConfig(t *testing.T) {
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
				Type:        domain.CTypeTPP,
				Credentials: domain.Authentication{PKCS12: "p12Auth"},
			},
		},
	}

	err := setPlaybookTLSConfig(playbook)
	assert.NoError(t, err)

	tlsCfg := http.DefaultTransport.(*http.Transport).TLSClientConfig

	assert.Equal(t, tls.RenegotiateFreelyAsClient, tlsCfg.Renegotiation)
	assert.False(t, tlsCfg.InsecureSkipVerify)

	p12, err := os.ReadFile(p12FileLocation)
	assert.NoError(t, err)

	blocks, err := pkcs12.ToPEM(p12, p12Password)
	assert.NoError(t, err)

	var pemData []byte
	for _, b := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	assert.NotEmpty(t, tlsCfg.Certificates)
	assert.Equal(t, 1, len(tlsCfg.Certificates))
	assert.Equal(t, 2, len(tlsCfg.Certificates[0].Certificate))
	assert.Equal(t, blocks[0].Bytes, tlsCfg.Certificates[0].Certificate[0])
	assert.Equal(t, blocks[1].Bytes, tlsCfg.Certificates[0].Certificate[1])
	assert.NotNil(t, tlsCfg.RootCAs)

}

func TestSetPlaybookTLSConfig_noP12Certificate(t *testing.T) {
	logName := "./logout.log"

	zc := zap.NewDevelopmentConfig()
	zc.Encoding = "json"
	zc.OutputPaths = []string{logName}
	l, err := zc.Build()
	assert.NoError(t, err)
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
				Type:        domain.CTypeTPP,
				Credentials: domain.Authentication{PKCS12: "p12Auth"},
				Insecure:    true,
			},
		},
	}

	err = setPlaybookTLSConfig(playbook)
	assert.NoError(t, err)

	tlsCfg := http.DefaultTransport.(*http.Transport).TLSClientConfig

	assert.Equal(t, tls.RenegotiateFreelyAsClient, tlsCfg.Renegotiation)
	assert.True(t, tlsCfg.InsecureSkipVerify)
	assert.Empty(t, tlsCfg.Certificates)
	assert.Nil(t, tlsCfg.RootCAs)

	f, err := os.Open("./logout.log")
	assert.NoError(t, err)

	warningFound := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		data := scanner.Bytes()
		line := logLine{}
		err = json.Unmarshal(data, &line)
		assert.NoError(t, err)

		level, err := zapcore.ParseLevel(line.Level)
		assert.NoError(t, err)

		if level == zapcore.WarnLevel {
			assert.Equal(t, "unable to read PKCS#12 file", line.Message)
			warningFound = true
			break
		}
	}
	err = f.Close()
	assert.NoError(t, err)

	err = os.Remove(logName)
	assert.NoError(t, err)

	assert.True(t, warningFound)
}

func TestSetPlaybookTLSConfig_noCertAuth(t *testing.T) {
	playbook := domain.Playbook{
		CertificateTasks: nil,
		Config: domain.Config{
			Connection: domain.Connection{
				Type:        domain.CTypeVaaS,
				Credentials: domain.Authentication{},
			},
		},
	}

	err := setPlaybookTLSConfig(playbook)
	assert.NoError(t, err)

	tlsCfg := http.DefaultTransport.(*http.Transport).TLSClientConfig

	assert.NotEqual(t, tls.RenegotiateFreelyAsClient, tlsCfg.Renegotiation)
	assert.False(t, tlsCfg.InsecureSkipVerify)
	assert.Empty(t, tlsCfg.Certificates)
	assert.Nil(t, tlsCfg.RootCAs)
}

func TestSetPlaybookTLSConfig_Insecure(t *testing.T) {
	playbook := domain.Playbook{
		CertificateTasks: nil,
		Config: domain.Config{
			Connection: domain.Connection{
				Insecure: true,
			},
		},
	}

	err := setPlaybookTLSConfig(playbook)
	assert.NoError(t, err)

	tlsCfg := http.DefaultTransport.(*http.Transport).TLSClientConfig
	assert.True(t, tlsCfg.InsecureSkipVerify)
}
