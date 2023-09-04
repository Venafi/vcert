/*
 * Copyright 2023 Venafi, Inc.
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

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v5/pkg/playbook/util"
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
func (r JKSInstaller) Check(renewBefore string, _ domain.PlaybookRequest) (bool, error) {
	zap.L().Info("checking certificate health", zap.String("format", r.Type.String()), zap.String("location", r.File))

	// Check certificate file exists
	certExists, err := util.FileExists(r.File)
	if err != nil {
		return false, err
	}
	if !certExists {
		return true, nil
	}

	keyPassword := r.KeyPassword
	if keyPassword == "" {
		keyPassword = r.JKSPassword
	}

	// Load Certificate
	cert, err := loadJKS(r.File, r.JKSAlias, r.JKSPassword, keyPassword)
	if err != nil {
		return false, err
	}

	// Check certificate expiration
	renew := needRenewal(cert, renewBefore)

	return renew, nil
}

// Backup takes the certificate request and backs up the current version prior to overwriting
func (r JKSInstaller) Backup() error {
	zap.L().Debug("backing up certificate", zap.String("location", r.File))

	// Check certificate file exists
	certExists, err := util.FileExists(r.File)
	if err != nil {
		return err
	}
	if !certExists {
		zap.L().Info("New certificate location specified, no back up taken")
		return nil
	}

	newLocation := fmt.Sprintf("%s.bak", r.File)

	err = util.CopyFile(r.File, newLocation)
	if err != nil {
		return err
	}

	zap.L().Info("certificate backed up", zap.String("location", r.File), zap.String("backupLocation", newLocation))
	return nil
}

// Install takes the certificate bundle and moves it to the location specified in the installer
func (r JKSInstaller) Install(pcc certificate.PEMCollection) error {
	zap.L().Debug("installing certificate", zap.String("location", r.File))

	// If no password is set for the Private Key, use the JKSPassword
	keyPassword := r.KeyPassword
	if keyPassword == "" {
		keyPassword = r.JKSPassword
	}

	content, err := packageAsJKS(pcc, keyPassword, r.JKSAlias, r.JKSPassword)
	if err != nil {
		zap.L().Error("could not package certificate as JKS", zap.Error(err))
		return err
	}

	err = util.WriteFile(r.File, content)
	if err != nil {
		return err
	}

	return nil
}

// AfterInstallActions runs any instructions declared in the Installer on a terminal.
//
// No validations happen over the content of the AfterAction string, so caution is advised
func (r JKSInstaller) AfterInstallActions() (string, error) {
	zap.L().Debug("running after-install actions", zap.String("location", r.File))

	result, err := util.ExecuteScript(r.AfterAction)
	return result, err
}

// InstallValidationActions runs any instructions declared in the Installer on a terminal and expects
// "0" for successful validation and "1" for a validation failure
// No validations happen over the content of the InstallValidation string, so caution is advised
func (r JKSInstaller) InstallValidationActions() (string, error) {
	zap.L().Debug("running install validation actions", zap.String("location", r.File))

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
		zap.L().Error("could not read JKS file", zap.String("jksFile", jksFile), zap.Error(err))
		return nil, err
	}
	defer func() {
		if err = f.Close(); err != nil {
			zap.L().Fatal("could not close JKS file", zap.String("jksFile", jksFile))
		}
	}()

	// Load JKS
	ks := keystore.New()
	err = ks.Load(f, []byte(jksPassword))
	if err != nil {
		zap.L().Error("could not load JKS resource", zap.String("jksFile", jksFile))
		return nil, err
	}

	//Load Private Key and Certificate chain
	pkEntry, err := ks.GetPrivateKeyEntry(jksAlias, []byte(pkPassword))
	if err != nil {
		zap.L().Error("could not retrieve Private Key from JKS", zap.String("jksAlias", jksAlias))
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
