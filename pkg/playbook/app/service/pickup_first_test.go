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

package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v5/pkg/playbook/app/vcertutil"
)

func TestNormalizeThumbprint(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"AA:BB:CC:DD", "AABBCCDD"},
		{"aa:bb:cc:dd", "AABBCCDD"},
		{"AA BB CC DD", "AABBCCDD"},
		{"aa.bb.cc.dd", "AABBCCDD"},
		{"AABBCCDD", "AABBCCDD"},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.expected, vcertutil.NormalizeThumbprint(tc.input))
		})
	}
}

func TestPickupFirst_Disabled(t *testing.T) {
	config := domain.Config{}
	task := domain.CertificateTask{
		Request: domain.PlaybookRequest{
			PickupFirst: false,
		},
	}
	handled, errs := pickupFirstAttempt(config, task)
	assert.False(t, handled)
	assert.Nil(t, errs)
}

func TestPickupFirst_ForceRenew(t *testing.T) {
	config := domain.Config{ForceRenew: true}
	task := domain.CertificateTask{
		Request: domain.PlaybookRequest{
			PickupFirst: true,
		},
	}
	handled, errs := pickupFirstAttempt(config, task)
	assert.False(t, handled)
	assert.Nil(t, errs)
}

func TestFirstInstalledCertInfo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pickup-first-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Generate self-signed certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := time.Now().Add(24 * time.Hour).Truncate(time.Second)

	template := x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}

	certDer, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	certFile := filepath.Join(tmpDir, "cert.pem")
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer})
	err = os.WriteFile(certFile, certPem, 0600)
	require.NoError(t, err)

	sum := sha1.Sum(certDer)
	expectedThumb := strings.ToUpper(hex.EncodeToString(sum[:]))

	installations := []domain.Installation{
		{
			Type: domain.FormatPEM,
			File: certFile,
		},
	}

	thumbprint, parsedNotAfter, ok := firstInstalledCertInfo(installations)
	assert.True(t, ok)
	assert.Equal(t, expectedThumb, thumbprint)
	assert.Equal(t, notAfter.Unix(), parsedNotAfter.Unix())
}

func TestFirstInstalledCertInfo_MissingFile(t *testing.T) {
	installations := []domain.Installation{
		{
			Type: domain.FormatPEM,
			File: "C:\\nonexistent\\path\\cert.pem",
		},
	}
	thumbprint, _, ok := firstInstalledCertInfo(installations)
	assert.False(t, ok)
	assert.Empty(t, thumbprint)
}

func TestKeyMatchesCert(t *testing.T) {
	// Generate key 1 and cert 1
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key1Der := x509.MarshalPKCS1PrivateKey(key1)
	key1Pem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: key1Der})

	// Generate key 2 (different key)
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key2Der := x509.MarshalPKCS1PrivateKey(key2)
	key2Pem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: key2Der})

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "app.example.com",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	certDer, err := x509.CreateCertificate(rand.Reader, &template, &template, &key1.PublicKey, key1)
	require.NoError(t, err)
	certPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer}))

	// 1. Matching key should return true
	assert.True(t, keyMatchesCert(certPem, key1Pem, ""))

	// 2. Mismatched key (different key) should return false
	assert.False(t, keyMatchesCert(certPem, key2Pem, ""))

	// 3. Empty inputs should return false
	assert.False(t, keyMatchesCert("", key1Pem, ""))
	assert.False(t, keyMatchesCert(certPem, nil, ""))
	assert.False(t, keyMatchesCert(certPem, []byte("invalid-key-data"), ""))
}

func resetHooks() {
	locateLatestCNFunc = vcertutil.LocateLatestCN
	pickupByLocatorFunc = vcertutil.PickupCertificateByLocator
	executeEnrollmentFunc = executeEnrollmentAndInstall
}

func createTestCertAndKey(t *testing.T, cn string, notBefore, notAfter time.Time) (string, []byte, string) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	certDer, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)
	certPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer}))
	keyDer := x509.MarshalPKCS1PrivateKey(privKey)
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDer})
	sum := sha1.Sum(certDer)
	thumb := strings.ToUpper(hex.EncodeToString(sum[:]))
	return certPem, keyPem, thumb
}

func TestPickupFirst_Contract001_AuthoritativePlatformState_RetiredCert(t *testing.T) {
	defer resetHooks()

	tmpDir, err := os.MkdirTemp("", "pickup-first-contract001-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Local cert is still valid for 180 days
	certPem, keyPem, _ := createTestCertAndKey(t, "retired-test.example.com", time.Now().Add(-1*time.Hour), time.Now().Add(180*24*time.Hour))
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, []byte(certPem), 0600))
	require.NoError(t, os.WriteFile(keyFile, keyPem, 0600))

	// Central platform has zero active certs (all RETIRED / REVOKED) -> loc.Found = false
	locateLatestCNFunc = func(config domain.Config, request domain.PlaybookRequest) (*vcertutil.LocateResult, error) {
		return &vcertutil.LocateResult{Found: false}, nil
	}

	enrollmentTriggered := false
	executeEnrollmentFunc = func(config domain.Config, task domain.CertificateTask) []error {
		enrollmentTriggered = true
		return nil
	}

	config := domain.Config{}
	task := domain.CertificateTask{
		Request: domain.PlaybookRequest{
			PickupFirst: true,
			Subject: domain.Subject{
				CommonName: "retired-test.example.com",
			},
		},
		Installations: []domain.Installation{
			{
				Type:    domain.FormatPEM,
				File:    certFile,
				KeyFile: keyFile,
			},
		},
	}

	handled, errs := pickupFirstAttempt(config, task)
	assert.True(t, handled, "pickupFirst should handle the retired certificate reconciliation")
	assert.Nil(t, errs)
	assert.True(t, enrollmentTriggered, "Contract 001 MUST trigger authoritative replacement enrollment when local cert is retired/revoked centrally")
}

func TestPickupFirst_LeaderNode_EmptyDisk_PlatformNotFound(t *testing.T) {
	defer resetHooks()

	// Platform has zero certs, and disk has no cert
	locateLatestCNFunc = func(config domain.Config, request domain.PlaybookRequest) (*vcertutil.LocateResult, error) {
		return &vcertutil.LocateResult{Found: false}, nil
	}

	enrollmentDirectlyCalled := false
	executeEnrollmentFunc = func(config domain.Config, task domain.CertificateTask) []error {
		enrollmentDirectlyCalled = true
		return nil
	}

	config := domain.Config{}
	task := domain.CertificateTask{
		Request: domain.PlaybookRequest{
			PickupFirst: true,
			Subject: domain.Subject{
				CommonName: "new-leader.example.com",
			},
		},
		Installations: []domain.Installation{
			{
				Type: domain.FormatPEM,
				File: filepath.Join(os.TempDir(), "non-existent-cert-file.pem"),
			},
		},
	}

	handled, errs := pickupFirstAttempt(config, task)
	assert.False(t, handled, "pickupFirst should return handled=false to let standard playbook enroll flow run")
	assert.Nil(t, errs)
	assert.False(t, enrollmentDirectlyCalled, "pickupFirst should not call executeEnrollment directly on empty disk not-found")
}

func TestPickupFirst_Match_DefersToRenewBefore(t *testing.T) {
	defer resetHooks()

	tmpDir, err := os.MkdirTemp("", "pickup-first-match-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	certPem, keyPem, thumb := createTestCertAndKey(t, "match.example.com", time.Now().Add(-1*time.Hour), time.Now().Add(30*24*time.Hour))
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, []byte(certPem), 0600))
	require.NoError(t, os.WriteFile(keyFile, keyPem, 0600))

	locateLatestCNFunc = func(config domain.Config, request domain.PlaybookRequest) (*vcertutil.LocateResult, error) {
		return &vcertutil.LocateResult{
			Found:      true,
			Thumbprint: thumb,
			ValidTo:    time.Now().Add(30 * 24 * time.Hour),
		}, nil
	}

	config := domain.Config{}
	task := domain.CertificateTask{
		Request: domain.PlaybookRequest{
			PickupFirst: true,
			Subject: domain.Subject{
				CommonName: "match.example.com",
			},
		},
		Installations: []domain.Installation{
			{
				Type:    domain.FormatPEM,
				File:    certFile,
				KeyFile: keyFile,
			},
		},
	}

	handled, errs := pickupFirstAttempt(config, task)
	assert.False(t, handled, "Matching thumbprint should defer (handled=false) to standard renewBefore fast check")
	assert.Nil(t, errs)
}

func TestPickupFirst_RefuseDowngrade(t *testing.T) {
	defer resetHooks()

	tmpDir, err := os.MkdirTemp("", "pickup-first-downgrade-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Local cert valid for 90 days
	certPem, keyPem, _ := createTestCertAndKey(t, "downgrade.example.com", time.Now().Add(-1*time.Hour), time.Now().Add(90*24*time.Hour))
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, []byte(certPem), 0600))
	require.NoError(t, os.WriteFile(keyFile, keyPem, 0600))

	// Platform cert is older (valid only for 10 days)
	locateLatestCNFunc = func(config domain.Config, request domain.PlaybookRequest) (*vcertutil.LocateResult, error) {
		return &vcertutil.LocateResult{
			Found:      true,
			Thumbprint: "DIFFERENT_THUMBPRINT",
			ValidTo:    time.Now().Add(10 * 24 * time.Hour),
		}, nil
	}

	config := domain.Config{}
	task := domain.CertificateTask{
		Request: domain.PlaybookRequest{
			PickupFirst: true,
			Subject: domain.Subject{
				CommonName: "downgrade.example.com",
			},
		},
		Installations: []domain.Installation{
			{
				Type:    domain.FormatPEM,
				File:    certFile,
				KeyFile: keyFile,
			},
		},
	}

	handled, errs := pickupFirstAttempt(config, task)
	assert.True(t, handled, "Downgrade should be handled (refused) cleanly")
	assert.Nil(t, errs)

	// Verify local cert was NOT touched or overwritten
	content, err := os.ReadFile(certFile)
	require.NoError(t, err)
	assert.Equal(t, certPem, string(content))
}

func TestPickupFirst_KeyMismatch_AutoEnrolls(t *testing.T) {
	defer resetHooks()

	tmpDir, err := os.MkdirTemp("", "pickup-first-keymismatch-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Disk has key1
	_, key1Pem, _ := createTestCertAndKey(t, "key1", time.Now(), time.Now().Add(24*time.Hour))
	keyFile := filepath.Join(tmpDir, "key.pem")
	certFile := filepath.Join(tmpDir, "cert.pem")
	require.NoError(t, os.WriteFile(keyFile, key1Pem, 0600))

	// Platform has cert2 (generated with key2, not key1) and no vaulted private key
	cert2Pem, _, _ := createTestCertAndKey(t, "key2-cert", time.Now(), time.Now().Add(72*time.Hour))

	locateLatestCNFunc = func(config domain.Config, request domain.PlaybookRequest) (*vcertutil.LocateResult, error) {
		return &vcertutil.LocateResult{
			Found:      true,
			Thumbprint: "PLATFORM_THUMB",
			ValidTo:    time.Now().Add(72 * time.Hour),
			ID:         "cert-uuid",
		}, nil
	}

	pickupByLocatorFunc = func(config domain.Config, request domain.PlaybookRequest, loc *vcertutil.LocateResult, keyPassword string, fetchKey bool) (*certificate.PEMCollection, *certificate.Request, error) {
		return &certificate.PEMCollection{
			Certificate: cert2Pem,
			PrivateKey:  "", // No vaulted private key
		}, &certificate.Request{}, nil
	}

	replacementTriggered := false
	executeEnrollmentFunc = func(config domain.Config, task domain.CertificateTask) []error {
		replacementTriggered = true
		return nil
	}

	config := domain.Config{}
	task := domain.CertificateTask{
		Request: domain.PlaybookRequest{
			PickupFirst: true,
			Subject: domain.Subject{
				CommonName: "app.example.com",
			},
		},
		Installations: []domain.Installation{
			{
				Type:    domain.FormatPEM,
				File:    certFile,
				KeyFile: keyFile,
			},
		},
	}

	handled, errs := pickupFirstAttempt(config, task)
	assert.True(t, handled)
	assert.Nil(t, errs)
	assert.True(t, replacementTriggered, "Key mismatch MUST automatically trigger replacement enrollment")
}

func TestPickupFirst_DiskKeyMatches_InstallsSuccessfully(t *testing.T) {
	defer resetHooks()

	tmpDir, err := os.MkdirTemp("", "pickup-first-keymatch-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Generate cert1 and key1
	cert1Pem, key1Pem, _ := createTestCertAndKey(t, "app.example.com", time.Now().Add(-1*time.Hour), time.Now().Add(72*time.Hour))
	keyFile := filepath.Join(tmpDir, "key.pem")
	certFile := filepath.Join(tmpDir, "cert.pem")
	chainFile := filepath.Join(tmpDir, "chain.pem")
	require.NoError(t, os.WriteFile(keyFile, key1Pem, 0600))

	locateLatestCNFunc = func(config domain.Config, request domain.PlaybookRequest) (*vcertutil.LocateResult, error) {
		return &vcertutil.LocateResult{
			Found:      true,
			Thumbprint: "PLATFORM_THUMB",
			ValidTo:    time.Now().Add(72 * time.Hour),
			ID:         "cert-uuid",
		}, nil
	}

	// Platform returns cert1 with no private key
	pickupByLocatorFunc = func(config domain.Config, request domain.PlaybookRequest, loc *vcertutil.LocateResult, keyPassword string, fetchKey bool) (*certificate.PEMCollection, *certificate.Request, error) {
		return &certificate.PEMCollection{
			Certificate: cert1Pem,
			PrivateKey:  "", // No vaulted private key
		}, &certificate.Request{}, nil
	}

	executeEnrollmentCalled := false
	executeEnrollmentFunc = func(config domain.Config, task domain.CertificateTask) []error {
		executeEnrollmentCalled = true
		return nil
	}

	config := domain.Config{}
	task := domain.CertificateTask{
		Request: domain.PlaybookRequest{
			PickupFirst: true,
			Subject: domain.Subject{
				CommonName: "app.example.com",
			},
		},
		Installations: []domain.Installation{
			{
				Type:      domain.FormatPEM,
				File:      certFile,
				KeyFile:   keyFile,
				ChainFile: chainFile,
			},
		},
	}

	handled, errs := pickupFirstAttempt(config, task)
	assert.True(t, handled)
	assert.Empty(t, errs)
	assert.False(t, executeEnrollmentCalled, "Should NOT trigger enrollment when matching disk key is bound")

	// Verify cert file was installed on disk
	installedCert, err := os.ReadFile(certFile)
	require.NoError(t, err)
	assert.Contains(t, string(installedCert), "BEGIN CERTIFICATE")
}

func TestPickupFirst_PlatformNewer_VaultedKey_InstallsSuccessfully(t *testing.T) {
	defer resetHooks()

	tmpDir, err := os.MkdirTemp("", "pickup-first-newer-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	chainFile := filepath.Join(tmpDir, "chain.pem")

	certPem, keyPem, thumb := createTestCertAndKey(t, "cluster.example.com", time.Now().Add(-1*time.Hour), time.Now().Add(90*24*time.Hour))

	locateLatestCNFunc = func(config domain.Config, request domain.PlaybookRequest) (*vcertutil.LocateResult, error) {
		return &vcertutil.LocateResult{
			Found:      true,
			Thumbprint: thumb,
			ValidTo:    time.Now().Add(90 * 24 * time.Hour),
			ID:         "platform-id",
		}, nil
	}

	pickupByLocatorFunc = func(config domain.Config, request domain.PlaybookRequest, loc *vcertutil.LocateResult, keyPassword string, fetchKey bool) (*certificate.PEMCollection, *certificate.Request, error) {
		return &certificate.PEMCollection{
			Certificate: certPem,
			PrivateKey:  string(keyPem),
		}, &certificate.Request{}, nil
	}

	config := domain.Config{}
	task := domain.CertificateTask{
		Request: domain.PlaybookRequest{
			PickupFirst: true,
			Subject: domain.Subject{
				CommonName: "cluster.example.com",
			},
		},
		Installations: []domain.Installation{
			{
				Type:      domain.FormatPEM,
				File:      certFile,
				KeyFile:   keyFile,
				ChainFile: chainFile,
			},
		},
	}

	handled, errs := pickupFirstAttempt(config, task)
	assert.True(t, handled)
	assert.Empty(t, errs)

	// Verify cert and key were written to disk
	installedCert, err := os.ReadFile(certFile)
	require.NoError(t, err)
	assert.Contains(t, string(installedCert), "BEGIN CERTIFICATE")

	installedKey, err := os.ReadFile(keyFile)
	require.NoError(t, err)
	assert.Contains(t, string(installedKey), "PRIVATE KEY")
}

func TestPickupFirst_LocatorErrors(t *testing.T) {
	defer resetHooks()

	config := domain.Config{}
	task := domain.CertificateTask{
		Request: domain.PlaybookRequest{
			PickupFirst: true,
			Subject:     domain.Subject{CommonName: "error.example.com"},
		},
	}

	// 1. ErrLocateNotSupported should gracefully fall through
	locateLatestCNFunc = func(config domain.Config, request domain.PlaybookRequest) (*vcertutil.LocateResult, error) {
		return nil, vcertutil.ErrLocateNotSupported
	}
	handled, errs := pickupFirstAttempt(config, task)
	assert.False(t, handled)
	assert.Nil(t, errs)

	// 2. Generic network/API error should gracefully fall through to enroll
	locateLatestCNFunc = func(config domain.Config, request domain.PlaybookRequest) (*vcertutil.LocateResult, error) {
		return nil, errors.New("network connection timeout")
	}
	handled, errs = pickupFirstAttempt(config, task)
	assert.False(t, handled)
	assert.Nil(t, errs)
}
