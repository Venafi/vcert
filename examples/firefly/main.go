package main

import (
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/util"
)

const (
	name    = "example-firefly-certificate-client"
	version = "v0.0.1"
)

func main() {
	userAgent := fmt.Sprintf("%s/%s %s", name, version, util.DefaultUserAgent)
	fireflyConfig := vcert.Config{
		ConnectorType: endpoint.ConnectorTypeFirefly,
		BaseUrl:       os.Getenv("FIREFLY_URL"),
		Credentials: &endpoint.Authentication{
			ClientId:     os.Getenv("FIREFLY_CLIENT_ID"),
			ClientSecret: os.Getenv("FIREFLY_CLIENT_SECRET"),
			IdentityProvider: &endpoint.OAuthProvider{
				TokenURL: os.Getenv("FIREFLY_TOKEN_URL"),
			},
		},
		Zone:      os.Getenv("FIREFLY_ZONE"),
		UserAgent: &userAgent,
	}

	trustBundleFilePath := os.Getenv("FIREFLY_TRUST_BUNDLE_PATH")
	if trustBundleFilePath != "" {
		buf, err := os.ReadFile(trustBundleFilePath)
		if err != nil {
			panic(err)
		}
		fireflyConfig.ConnectionTrust = string(buf)
	}

	connector, err := vcert.NewClient(&fireflyConfig)
	if err != nil {
		log.Fatalf("error creating client: %s", err.Error())
	}
	request := &certificate.Request{
		Subject: pkix.Name{
			CommonName:         "common.name.venafi.example.com",
			Organization:       []string{"Venafi.com"},
			OrganizationalUnit: []string{"Integration Team"},
			Locality:           []string{"Salt Lake"},
			Province:           []string{"Salt Lake"},
			Country:            []string{"US"},
		},
		DNSNames:  []string{"www.client.venafi.example.com", "ww1.client.venafi.example.com"},
		CsrOrigin: certificate.ServiceGeneratedCSR,
		KeyType:   certificate.KeyTypeECDSA,
		KeyCurve:  certificate.EllipticCurveP256,
	}

	pcc, err := connector.SynchronousRequestCertificate(request)
	if err != nil {
		log.Fatalf("error requesting certificate: %s", err.Error())
	}
	pp(pcc)
}

var pp = func(a interface{}) {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		fmt.Println("error: ", err)
	}
	log.Println(string(b))
}
