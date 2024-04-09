package main

import (
	"crypto/x509/pkix"
	"fmt"
	"log"
	"os"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/util"
)

const (
	vcpURL      = "VCP_URL"
	vcpZone     = "VCP_ZONE"
	vcpTokenURL = "VCP_TOKEN_URL"
	vcpJWT      = "VCP_JWT"

	envVarNotSet = "environment variable not set: %s"

	name    = "example-tlspc-service-account-client"
	version = "v0.0.1"
)

func main() {

	// URL can be nil if using production TLSPC
	url := os.Getenv(vcpURL)

	zone, found := os.LookupEnv(vcpZone)
	if !found {
		log.Fatalf(envVarNotSet, vcpZone)
	}
	tokenURL, found := os.LookupEnv(vcpTokenURL)
	if !found {
		log.Fatalf(envVarNotSet, vcpTokenURL)
	}
	jwt, found := os.LookupEnv(vcpJWT)
	if !found {
		log.Fatalf(envVarNotSet, vcpJWT)
	}

	userAgent := fmt.Sprintf("%s/%s %s", name, version, util.DefaultUserAgent)
	config := &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeCloud,
		BaseUrl:       url,
		Zone:          zone,
		Credentials: &endpoint.Authentication{
			ExternalJWT: jwt,
			TokenURL:    tokenURL,
		},
		UserAgent: &userAgent,
	}
	connector, err := vcert.NewClient(config)
	if err != nil {
		log.Fatalf("error creating client: %s", err.Error())
	}

	_, err = connector.ReadZoneConfiguration()
	if err != nil {
		log.Fatalf("error reading zone: %s", err.Error())

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
