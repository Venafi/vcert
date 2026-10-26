package fake

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/Venafi/vcert/v5/pkg/certificate"
)

func TestRequestAndRetrieveMLDSACertificate(t *testing.T) {
	for _, strength := range certificate.AllSupportedMLDSAStrengths() {
		t.Run(fmt.Sprintf("ML-DSA-%d", strength), func(t *testing.T) {
			conn := getTestConnector()
			zoneConfig, err := conn.ReadZoneConfiguration()
			if err != nil {
				t.Fatal(err)
			}
			req := &certificate.Request{CsrOrigin: certificate.LocalGeneratedCSR, KeyType: certificate.KeyTypeMLDSA, KeyLength: strength}
			req.Subject.CommonName = "mldsa.venafi.example.com"
			req.Subject.Organization = []string{"Venafi, Inc."}
			req.Subject.OrganizationalUnit = []string{"Automated Tests"}
			if err := zoneConfig.ValidateCertificateRequest(req); err != nil {
				t.Fatalf("validate: %s", err)
			}
			if err := conn.GenerateRequest(zoneConfig, req); err != nil {
				t.Fatalf("generate: %s", err)
			}
			pickupID, err := conn.RequestCertificate(req)
			if err != nil {
				t.Fatalf("request: %s", err)
			}
			req.PickupID = pickupID
			req.ChainOption = certificate.ChainOptionRootLast
			pcc, err := conn.RetrieveCertificate(req)
			if err != nil {
				t.Fatalf("retrieve: %s", err)
			}
			if err := req.CheckCertificate(pcc.Certificate); err != nil {
				t.Fatalf("check: %s", err)
			}
			block, _ := pem.Decode([]byte(pcc.Certificate))
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if cert.PublicKeyAlgorithm != x509.MLDSA {
				t.Fatalf("unexpected public key algorithm %s", cert.PublicKeyAlgorithm)
			}
			if err := pcc.AddPrivateKey(req.PrivateKey, []byte("s3cret!")); err != nil {
				t.Fatalf("add private key: %s", err)
			}
		})
	}
}
