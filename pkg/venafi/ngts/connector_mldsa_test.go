//go:build integration

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

// ML-DSA certificate requests against a live NGTS tenant. They need NGTS_ZONE_MLDSA, an issuing template that allows
// ML-DSA 44, 65 and 87, and are skipped without it. Service generated keys also need an active VSatellite in the tenant.

package ngts

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/test"
)

const mldsaTestKeyPassword = "Passw0rd-MLDSA"

func getMLDSATestConnector(t *testing.T) (*Connector, *endpoint.ZoneConfiguration) {
	t.Helper()
	if ctx.NGTSZoneMLDSA == "" {
		t.Skip("NGTS_ZONE_MLDSA is not set; it must name an issuing template that allows ML-DSA")
	}
	conn := getTestConnector(ctx.NGTSZoneMLDSA)
	require.NoError(t, authenticateTestConnector(conn))
	zoneConfig, err := conn.ReadZoneConfiguration()
	require.NoError(t, err)
	return conn, zoneConfig
}

func newMLDSATestRequest() *certificate.Request {
	req := &certificate.Request{}
	req.Subject.CommonName = test.RandSpecificCN("vfidev.com")
	req.DNSNames = []string{req.Subject.CommonName}
	req.KeyType = certificate.KeyTypeMLDSA
	req.ChainOption = certificate.ChainOptionRootLast
	req.Timeout = 180 * time.Second
	return req
}

// requireMLDSACertificate checks that the certificate has an ML-DSA public key of the given strength, and returns it
func requireMLDSACertificate(t *testing.T, pcc *certificate.PEMCollection, strength int) *mldsa.PublicKey {
	t.Helper()
	require.NotNil(t, pcc)
	block, _ := pem.Decode([]byte(pcc.Certificate))
	require.NotNil(t, block, "the certificate is not PEM")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, x509.MLDSA, cert.PublicKeyAlgorithm)
	pub, ok := cert.PublicKey.(*mldsa.PublicKey)
	require.True(t, ok, "unexpected public key type %T", cert.PublicKey)
	require.Equal(t, strength, certificate.MLDSAStrength(pub))
	require.NotEmpty(t, pcc.Chain, "the certificate chain is empty")
	return pub
}

func requireSamePublicKey(t *testing.T, expected crypto.PublicKey, actual *mldsa.PublicKey) {
	t.Helper()
	expectedMLDSA, ok := expected.(*mldsa.PublicKey)
	require.True(t, ok, "unexpected public key type %T", expected)
	require.True(t, expectedMLDSA.Equal(actual), "the certificate public key doesn't match the request key")
}

func TestReadZoneConfigurationMLDSA(t *testing.T) {
	_, zoneConfig := getMLDSATestConnector(t)

	var strengths []int
	for _, kc := range zoneConfig.Policy.AllowedKeyConfigurations {
		if kc.KeyType == certificate.KeyTypeMLDSA {
			strengths = kc.KeySizes
		}
	}
	require.ElementsMatch(t, certificate.AllSupportedMLDSAStrengths(), strengths, "the issuing template should allow every ML-DSA strength")
	require.NotZero(t, zoneConfig.DefaultMLDSAStrength())
}

func TestRequestCertificateMLDSALocalGeneratedCSR(t *testing.T) {
	conn, zoneConfig := getMLDSATestConnector(t)

	for _, strength := range certificate.AllSupportedMLDSAStrengths() {
		t.Run(fmt.Sprintf("ML-DSA-%d", strength), func(t *testing.T) {
			req := newMLDSATestRequest()
			req.KeyStrength = strength
			req.CsrOrigin = certificate.LocalGeneratedCSR

			require.NoError(t, zoneConfig.ValidateCertificateRequest(req))
			zoneConfig.UpdateCertificateRequest(req)
			require.NoError(t, conn.GenerateRequest(zoneConfig, req))

			pickupID, err := conn.RequestCertificate(req)
			require.NoError(t, err)
			req.PickupID = pickupID

			pcc, err := retrieveCertificate(conn, req, 180)
			require.NoError(t, err)
			pub := requireMLDSACertificate(t, pcc, strength)
			requireSamePublicKey(t, req.PrivateKey.Public(), pub)
		})
	}
}

func TestRequestCertificateMLDSAUserProvidedCSR(t *testing.T) {
	conn, zoneConfig := getMLDSATestConnector(t)

	for _, strength := range certificate.AllSupportedMLDSAStrengths() {
		t.Run(fmt.Sprintf("ML-DSA-%d", strength), func(t *testing.T) {
			// the CSR is created outside of vcert, as a user would with their own tooling
			key, err := certificate.GenerateMLDSAPrivateKey(strength)
			require.NoError(t, err)
			cn := test.RandSpecificCN("vfidev.com")
			csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: cn},
				DNSNames: []string{cn},
			}, key)
			require.NoError(t, err)

			req := &certificate.Request{
				CsrOrigin:   certificate.UserProvidedCSR,
				ChainOption: certificate.ChainOptionRootLast,
				Timeout:     180 * time.Second,
			}
			require.NoError(t, req.SetCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})))
			require.NoError(t, zoneConfig.ValidateCertificateRequest(req))
			require.NoError(t, conn.GenerateRequest(zoneConfig, req))

			pickupID, err := conn.RequestCertificate(req)
			require.NoError(t, err)
			req.PickupID = pickupID

			pcc, err := retrieveCertificate(conn, req, 180)
			require.NoError(t, err)
			pub := requireMLDSACertificate(t, pcc, strength)
			requireSamePublicKey(t, key.Public(), pub)
		})
	}
}

// requestServiceGeneratedMLDSA requests a certificate with an ML-DSA key generated by NGTS, and checks the certificate
// and the encrypted private key it returns
func requestServiceGeneratedMLDSA(t *testing.T, conn *Connector, zoneConfig *endpoint.ZoneConfiguration, req *certificate.Request, strength int) {
	t.Helper()
	req.CsrOrigin = certificate.ServiceGeneratedCSR
	req.KeyPassword = mldsaTestKeyPassword

	require.NoError(t, conn.GenerateRequest(zoneConfig, req))
	require.Equal(t, strength, req.KeyStrength)

	pickupID, err := conn.RequestCertificate(req)
	require.NoError(t, err)
	req.PickupID = pickupID

	pcc, err := conn.RetrieveCertificate(req)
	require.NoError(t, err)
	pub := requireMLDSACertificate(t, pcc, strength)

	block, _ := pem.Decode([]byte(pcc.PrivateKey))
	require.NotNil(t, block, "the private key is not PEM")
	require.Equal(t, "ENCRYPTED PRIVATE KEY", block.Type)
	key, err := util.ParsePKCS8PrivateKey(block.Bytes, []byte(mldsaTestKeyPassword))
	require.NoError(t, err)
	signer, ok := key.(crypto.Signer)
	require.True(t, ok, "unexpected private key type %T", key)
	requireSamePublicKey(t, signer.Public(), pub)
}

func TestRequestCertificateMLDSAServiceGeneratedCSR(t *testing.T) {
	conn, zoneConfig := getMLDSATestConnector(t)

	for _, strength := range certificate.AllSupportedMLDSAStrengths() {
		t.Run(fmt.Sprintf("ML-DSA-%d", strength), func(t *testing.T) {
			req := newMLDSATestRequest()
			req.KeyStrength = strength
			requestServiceGeneratedMLDSA(t, conn, zoneConfig, req, strength)
		})
	}
}

func TestRequestCertificateMLDSAServiceGeneratedCSRDefaultStrength(t *testing.T) {
	conn, zoneConfig := getMLDSATestConnector(t)

	// without a strength, the issuing template's recommended ML-DSA strength is used, else the lowest it allows
	req := newMLDSATestRequest()
	requestServiceGeneratedMLDSA(t, conn, zoneConfig, req, zoneConfig.DefaultMLDSAStrength())
}
