package main

import (
	"crypto/x509/pkix"
	"log"
	"os"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

const (
	TlspcUrl      = "TLSPC_URL"
	TlspcZone     = "TLSPC_ZONE"
	TlspcTenantId = "TLSPC_TENANT_ID"
	TlspcJwt      = "TLSPC_JWT"

	envVarNotSet = "environment variable not set: %s"
)

func main() {

	// URL can be nil if using production TLSPC
	url := os.Getenv(TlspcUrl)

	zone, found := os.LookupEnv(TlspcZone)
	if !found {
		log.Fatalf(envVarNotSet, TlspcZone)
	}
	tenantID, found := os.LookupEnv(TlspcTenantId)
	if !found {
		log.Fatalf(envVarNotSet, TlspcTenantId)
	}
	jwt, found := os.LookupEnv(TlspcJwt)
	if !found {
		log.Fatalf(envVarNotSet, TlspcJwt)
	}

	config := &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeCloud,
		BaseUrl:       url,
		Zone:          zone,
		Credentials: &endpoint.Authentication{
			TenantID:       tenantID,
			ExternalIdPJWT: jwt,
		},
	}
	connector, err := vcert.NewClient(config)
	if err != nil {
		log.Fatalf("error creating client: %s", err.Error())
	}

	request := &certificate.Request{
		Subject: pkix.Name{
			CommonName: "svc-account.venafi.example.com",
		},
		CsrOrigin: certificate.ServiceGeneratedCSR,
		KeyType:   certificate.KeyTypeRSA,
		KeyLength: 2048,
	}

	certID, err := connector.RequestCertificate(request)
	if err != nil {
		log.Fatalf("error requesting certificate: %s", err.Error())
	}
	log.Printf("certificate requested with ID: %s", certID)

	pcc, err := connector.RetrieveCertificate(request)
	if err != nil {
		log.Fatalf("error retrieving certificate: %s", err.Error())
	}
	log.Printf("Certificate:\n%s", pcc.Certificate)
}
