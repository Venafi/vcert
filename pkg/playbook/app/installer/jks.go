package installer

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/pavel-v-chernykh/keystore-go/v4"
	"go.uber.org/zap"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v4/pkg/playbook/util"
)

// JKSInstaller represents an installation that will use the Java KeyStore format for the certificate bundle
type JKSInstaller struct {
	domain.Installation
}

// NewJKSInstaller returns a new installer of type JKS with the values defined in inst
func NewJKSInstaller(inst domain.Installation) JKSInstaller {
	return JKSInstaller{inst}
}

// Check is the method in charge of making the validations to install a new certificate:
// 1. Does the certificate exists? > Install if it doesn't.
// 2. Does the certificate is about to expire? Renew if about to expire.
// Returns true if the certificate needs to be installed.
func (r JKSInstaller) Check(_ string, renewBefore string, request domain.PlaybookRequest) (bool, error) {
	zap.L().Debug(fmt.Sprintf("checking certificate at: %s", r.Location))

	// Check certificate file exists
	certExists, err := util.FileExists(r.Location)
	if err != nil {
		return false, err
	}
	if !certExists {
		return true, nil
	}

	//If no jksPassword set, use keyPassword
	jksPass := r.JKSPassword
	if jksPass == "" {
		jksPass = request.KeyPassword
	}

	// Load Certificate
	cert, err := loadJKS(r.Location, r.JKSAlias, jksPass, request.KeyPassword)
	if err != nil {
		return false, err
	}

	// Check certificate expiration
	renew := needRenewal(cert, renewBefore)

	return renew, nil
}

// Prepare takes the certificate, chain and private key and converts them to the specific format required for the installer
func (r JKSInstaller) Prepare(request certificate.Request, pcc certificate.PEMCollection) (*certificate.PEMCollection, error) {
	return prepareCertificateForBundle(request, pcc)
}

// Backup takes the certificate request and backs up the current version prior to overwriting
func (r JKSInstaller) Backup(_ string, request certificate.Request) error {

	zap.L().Debug(fmt.Sprintf("backing up certificate at: %s", r.Location))

	// Check certificate file exists
	certExists, err := util.FileExists(r.Location)
	if err != nil {
		return err
	}
	if !certExists {
		zap.L().Info(fmt.Sprintf("new certificate location specified, no back up taken"))
		return nil
	}

	//If no jksPassword set, use keyPassword
	jksPass := r.JKSPassword
	if jksPass == "" {
		jksPass = request.KeyPassword
	}

	newLocation := fmt.Sprintf("%s.bak", r.Location)

	err = util.CopyFile(r.Location, newLocation)

	return err
}

// Install takes the certificate bundle and moves it to the location specified in the installer
func (r JKSInstaller) Install(_ string, request certificate.Request, pcc certificate.PEMCollection) error {
	content, err := packageAsJKS(pcc, request.KeyPassword, r.JKSAlias, r.JKSPassword)
	if err != nil {
		zap.L().Error("could not package certificate as JKS")
		return err
	}

	err = util.WriteFile(r.Location, content)
	if err != nil {
		return err
	}

	return nil
}

// AfterInstallActions runs any instructions declared in the Installer on a terminal.
//
// No validations happen over the content of the AfterAction string, so caution is advised
func (r JKSInstaller) AfterInstallActions() error {
	_, err := util.ExecuteScript(r.AfterAction)
	return err
}

// InstallValidationActions runs any instructions declared in the Installer on a terminal and expects
// "0" for successful validation and "1" for a validation failure
// No validations happen over the content of the InstallValidation string, so caution is advised
func (r JKSInstaller) InstallValidationActions() (string, error) {
	validationResult, err := util.ExecuteScript(r.InstallValidation)
	if err != nil {
		return "", err
	}

	return validationResult, err
}

func loadJKS(jksFile string, jksAlias string, jksPassword string, pkPassword string) (*x509.Certificate, error) {
	//Open file
	f, err := os.Open(jksFile)
	if err != nil {
		zap.L().Error(fmt.Sprintf("could not read JKS file at: %s", jksFile))
		return nil, err
	}
	defer func() {
		if err = f.Close(); err != nil {
			zap.L().Fatal(fmt.Sprintf("could not close JKS file at %s", jksFile))
		}
	}()

	// Load JKS
	ks := keystore.New()
	err = ks.Load(f, []byte(jksPassword))
	if err != nil {
		zap.L().Error(fmt.Sprintf("could not load JKS resource at: %s", jksFile))
		return nil, err
	}

	//Load Private Key and Certificate chain
	pkEntry, err := ks.GetPrivateKeyEntry(jksAlias, []byte(pkPassword))
	if err != nil {
		zap.L().Error(fmt.Sprintf("could not retrieve Private Key with alias %s from JKS", jksAlias))
		return nil, err
	}

	certData := pkEntry.CertificateChain[0]

	cert, err := x509.ParseCertificate(certData.Content)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate: %w", err)
	}

	return cert, nil
}

func packageAsJKS(pcc certificate.PEMCollection, keyPassword string, jksAlias string, jksPassword string) ([]byte, error) {
	if len(pcc.Certificate) == 0 || len(pcc.PrivateKey) == 0 {
		return nil, fmt.Errorf("certificate and Private Key are required for JKS")
	}

	//Getting the certificate in bytes
	certBlock, _ := pem.Decode([]byte(pcc.Certificate))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no Certificate found on Certificate content")
	}

	//Adding the certificates to the slice of Certificates
	certificateChain := make([]keystore.Certificate, 0)
	certificateChain = append(certificateChain, keystore.Certificate{
		Type:    "X509",
		Content: certBlock.Bytes,
	})

	//Getting chain as keystore.Certificate objects
	certificateChain = append(certificateChain, getJKSCertChain(pcc.Chain)...)

	//Getting the Private Key
	privateKey, err := getPrivateKey(pcc.PrivateKey, keyPassword)
	if err != nil {
		return nil, err
	}

	//Marshalling the Private Key to PKCS8, which is mandatory for JKS format
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("error marshalling the private key to PKCS8: %w", err)
	}

	//creating a Private Key entry
	pkEntry := keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       pkcs8DER,
		CertificateChain: certificateChain,
	}

	//Adding the Private Key entry to the JKS
	keyStore := keystore.New()
	err = keyStore.SetPrivateKeyEntry(jksAlias, pkEntry, []byte(keyPassword))
	if err != nil {
		return nil, fmt.Errorf("JKS private key error: %w", err)
	}

	//Setting storePassword as keyPassword if jksPassword not defined
	var storePassword []byte
	if jksPassword != "" {
		storePassword = []byte(jksPassword)
	} else {
		storePassword = []byte(keyPassword)
	}

	//Storing the JKS to the buffer
	buffer := new(bytes.Buffer)
	err = keyStore.Store(buffer, storePassword)
	if err != nil {
		return nil, fmt.Errorf("JKS keystore error: %w", err)
	}

	return buffer.Bytes(), nil
}

func getJKSCertChain(chain []string) []keystore.Certificate {
	certificateChain := make([]keystore.Certificate, 0)
	//Getting each certificate in the chain and adding their bytes to the JKS chain
	for _, chainCert := range chain {
		chainBlock, _ := pem.Decode([]byte(chainCert))
		certificateChain = append(certificateChain, keystore.Certificate{
			Type:    "X509",
			Content: chainBlock.Bytes,
		})
	}

	return certificateChain
}
