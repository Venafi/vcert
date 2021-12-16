/*
 * Copyright 2020-2021 Venafi, Inc.
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
 *
 *
 * This functionality is based on the example that exists on this url:
 * https://github.com/eggsampler/acme/blob/master/examples/certbot/certbot.go
 *
 */

package venafi_acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/eggsampler/acme/v3"
	"github.com/takama/daemon"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func RequestAcmeCertificate(r *AcmeRequest) (*AcmeResponse, error) {

	if r.Domains == "" {
		log.Fatal("domains are required")
	}

	if _, err := os.Stat(r.Webroot); os.IsNotExist(err) {
		log.Fatalf("Webroot does not exist: %q", r.Webroot)
	}

	log.Printf("Connecting to acme directory url: %s", r.DirUrl)
	client, err := acme.NewClient(r.DirUrl)
	if err != nil {
		log.Fatalf("Error connecting to acme directory: %v", err)
	}

	// attempt to load an existing account from file
	log.Printf("Loading account file %s", r.AccountFile)
	account, err := loadAccount(client, r)
	if err != nil {
		log.Printf("Error loading existing account: %v", err)
		// if there was an error loading an account, just create a new one
		log.Printf("Creating a new account")
		account, err = createAccount(client, r)
		if err != nil {
			log.Fatalf("Error creaing new account: %v", err)
		}
	}
	log.Printf("Account url: %s", account.URL)

	// prepend the .well-known/acme-challenge path to the webroot path
	webroot := filepath.Join(r.Webroot, ".well-known", "acme-challenge")
	if _, err := os.Stat(webroot); os.IsNotExist(err) {
		log.Printf("Making directory path: %s", webroot)
		if err := os.MkdirAll(webroot, 0755); err != nil {
			log.Fatalf("Error creating webroot path %q: %v", webroot, err)
		}
	}

	domainList := strings.Split(r.Domains, ",")
	var ids []acme.Identifier
	for _, domain := range domainList {
		ids = append(ids, acme.Identifier{Type: "dns", Value: domain})
	}

	log.Printf("Creating new order for domains: %s", domainList)
	order, err := client.NewOrder(account, ids)
	if err != nil {
		log.Fatalf("Error creating new order: %v", err)
	}
	log.Printf("Order created: %s", order.URL)

	// loop through each of the provided authorization urls
	for _, authUrl := range order.Authorizations {
		// fetch the authorization data from the acme service given the provided authorization url
		log.Printf("Fetching authorization: %s", authUrl)
		auth, err := client.FetchAuthorization(account, authUrl)
		if err != nil {
			log.Fatalf("Error fetching authorization url %q: %v", authUrl, err)
		}
		log.Printf("Fetched authorization: %s", auth.Identifier.Value)

		// grab a http-01 challenge from the authorization if it exists
		chal, ok := auth.ChallengeMap[acme.ChallengeTypeHTTP01]
		if !ok {
			log.Fatalf("Unable to find http challenge for auth %s", auth.Identifier.Value)
		}

		// create the challenge token file with the key authorization from the challenge
		tokenFile := filepath.Join(webroot, chal.Token)
		log.Printf("Creating challenge token file: %s", tokenFile)
		defer os.Remove(tokenFile)
		if err := ioutil.WriteFile(tokenFile, []byte(chal.KeyAuthorization), 0644); err != nil {
			log.Fatalf("Error writing authorization %s challenge file %q: %v", auth.Identifier.Value, tokenFile, err)
		}

		// update the acme server that the challenge file is ready to be queried
		log.Printf("Updating challenge for authorization %s: %s", auth.Identifier.Value, chal.URL)
		chal, err = client.UpdateChallenge(account, chal)
		if err != nil {
			log.Fatalf("Error updating authorization %s challenge: %v", auth.Identifier.Value, err)
		}
		log.Printf("Challenge updated")
	}
	// all the challenges should now be completed

	// Load the private key from file
	var certKey *ecdsa.PrivateKey
	if r.ReuseKey {
		b, err := ioutil.ReadFile(r.KeyFile)
		if err != nil {
			log.Fatalf("Error reading key file %q: %v", r.KeyFile, err)
		}
		certKey = pem2key(b)
	} else {
		// generate a private key for the new certificate
		log.Printf("Generating certificate private key")
		certKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("Error generating certificate key: %v", err)
		}
		b := key2pem(certKey)
		// write the key to the key file as a pem encoded key
		log.Printf("Writing key file: %s", r.KeyFile)
		if err := ioutil.WriteFile(r.KeyFile, b, 0600); err != nil {
			log.Fatalf("Error writing key file %q: %v", r.KeyFile, err)
		}
	}

	// create the new csr template
	log.Printf("Creating csr")
	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          certKey.Public(),
		Subject:            pkix.Name{CommonName: domainList[0]},
		DNSNames:           domainList,
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, tpl, certKey)
	if err != nil {
		log.Fatalf("Error creating certificate request: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		log.Fatalf("Error parsing certificate request: %v", err)
	}

	// finalize the order with the acme server given a csr
	log.Printf("Finalising order: %s", order.URL)
	order, err = client.FinalizeOrder(account, order, csr)
	if err != nil {
		log.Fatalf("Error finalizing order: %v", err)
	}

	// fetch the certificate chain from the finalized order provided by the acme server
	log.Printf("Fetching certificate: %s", order.Certificate)
	certs, err := client.FetchCertificates(account, order.Certificate)
	if err != nil {
		log.Fatalf("Error fetching order certificates: %v", err)
	}

	// write the pem encoded certificate chain to file
	log.Printf("Saving certificate to: %s", r.CertFile)
	var pemData []string

	pemData = append(pemData, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certs[0].Raw,
	}))))

	if err := ioutil.WriteFile(r.CertFile, []byte(strings.Join(pemData, "\n")), 0600); err != nil {
		log.Fatalf("Error writing certificate file %q: %v", r.CertFile, err)
	}

	log.Printf("Finished.")
	return nil, nil
}

func RenewAcmeCertificate(req *AcmeRequest) (*AcmeResponse, error) {
	_, err := RequestAcmeCertificate(req)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func loadAccount(client acme.Client, r *AcmeRequest) (acme.Account, error) {
	raw, err := ioutil.ReadFile(r.AccountFile)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error reading account file %q: %v", r.AccountFile, err)
	}
	var aaf acmeAccountFile
	if err := json.Unmarshal(raw, &aaf); err != nil {
		return acme.Account{}, fmt.Errorf("error parsing account file %q: %v", r.AccountFile, err)
	}
	account, err := client.UpdateAccount(acme.Account{PrivateKey: pem2key([]byte(aaf.PrivateKey)), URL: aaf.Url}, getContacts(r)...)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error updating existing account: %v", err)
	}
	return account, nil
}

func createAccount(client acme.Client, r *AcmeRequest) (acme.Account, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error creating private key: %v", err)
	}
	account, err := client.NewAccount(privKey, false, true, getContacts(r)...)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error creating new account: %v", err)
	}
	raw, err := json.Marshal(acmeAccountFile{PrivateKey: string(key2pem(privKey)), Url: account.URL})
	if err != nil {
		return acme.Account{}, fmt.Errorf("error parsing new account: %v", err)
	}
	if err := ioutil.WriteFile(r.AccountFile, raw, 0600); err != nil {
		return acme.Account{}, fmt.Errorf("error creating account file: %v", err)
	}
	return account, nil
}

func getContacts(r *AcmeRequest) []string {
	var contacts []string
	if r.Contact != "" {
		contacts = strings.Split(r.Contact, ",")
		for i := 0; i < len(contacts); i++ {
			contacts[i] = "mailto:" + contacts[i]
		}
	}
	return contacts
}

func key2pem(certKey *ecdsa.PrivateKey) []byte {
	certKeyEnc, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		log.Fatalf("Error encoding key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: certKeyEnc,
	})
}

func pem2key(data []byte) *ecdsa.PrivateKey {
	b, _ := pem.Decode(data)
	key, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		log.Fatalf("Error decoding key: %v", err)
	}
	return key
}

const commandPattern = "" +
	"[Unit]\n" +
	"Description=%s\n\n" +
	"[Service]\n" +
	"Restart=always\n" +
	"RestartSec=60s\n" +
	"ExecStart={{.Path}} acme-renew --domains %s --renew-window %d -k %s -z \"%s\" --account \"%s\" --cert-file \"%s\" --key-file \"%s\"\n\n" +
	"[Install]\n" +
	"WantedBy=multi-user.target"

func SetupRenewalService(req *AcmeRenewSvcRequest) error {
	name := "vcert-renew-svc"
	description := fmt.Sprintf("Vcert Renew Service for ACME certificate [%s]", req.Domains)
	service, err := daemon.New(name, description, daemon.SystemDaemon)
	if err != nil {
		log.Fatal("Error: ", err)
	}

	escapedZone := strings.ReplaceAll(req.Zone, "\\", "\\\\")

	bar := fmt.Sprintf(commandPattern, description, req.Domains, req.RenewWindow, req.ApiKey, escapedZone, req.AccountFile, req.CertFile, req.KeyFile)

	log.Printf("Service Template is:")
	log.Println(bar)
	err = service.SetTemplate(bar)
	if err != nil {
		return err
	}

	status, err := service.Install()
	if err != nil {
		log.Fatal(status, "\nError: ", err)
	}
	fmt.Println(status)
	status, err = service.Start()

	return nil
}

func ParsePEMBundle(bundle []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	var certDERBlock *pem.Block

	for {
		certDERBlock, bundle = pem.Decode(bundle)
		if certDERBlock == nil {
			break
		}

		if certDERBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(certDERBlock.Bytes)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, cert)
		}
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("no certificates were found while parsing the bundle")
	}

	return certificates, nil
}
