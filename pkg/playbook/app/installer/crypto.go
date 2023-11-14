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
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/playbook/app/vcertutil"
	"github.com/Venafi/vcert/v5/pkg/util"
)

// DayDuration represents a day (24 hours) in the Duration type
const DayDuration = time.Hour * 24

type Certificate struct {
	X509cert   x509.Certificate
	Thumbprint string
}

func getPrivateKey(privateKeyStr string, keyPassword string) (interface{}, error) {
	//Getting Private Key
	pkBlock, _ := pem.Decode([]byte(privateKeyStr))
	if pkBlock == nil {
		return nil, fmt.Errorf("missing Private Key PEM")
	}

	var err error
	//Decrypting Private Key
	pkDER := pkBlock.Bytes
	if util.X509IsEncryptedPEMBlock(pkBlock) {
		pkDER, err = util.X509DecryptPEMBlock(pkBlock, []byte(keyPassword))
		if err != nil {
			return nil, fmt.Errorf("private key decryption error: %w", err)
		}
	}

	//Unmarshalling the Private Key
	var privateKey interface{}
	switch pkBlock.Type {
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(pkDER)
		if err != nil {
			privateKey, err = x509.ParsePKCS8PrivateKey(pkDER)
		}
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(pkDER)
		if err != nil {
			privateKey, err = x509.ParsePKCS8PrivateKey(pkDER)
		}
	default:
		return nil, fmt.Errorf("unexpected Private Key type: %s", pkBlock.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("private key error: %w", err)
	}

	return privateKey, nil
}

func prepareCertificateForBundle(request certificate.Request, pcc certificate.PEMCollection, decryptPK bool) (*certificate.PEMCollection, error) {
	// Private key generated locally. Need to add it to the PEM Collection
	if request.CsrOrigin == certificate.LocalGeneratedCSR {
		err := pcc.AddPrivateKey(request.PrivateKey, []byte(request.KeyPassword), "")
		if err != nil {
			return nil, err
		}
		zap.L().Debug("CSR Origin is [local]. Private Key added to PEM Collection")
	}

	// Key needs to be decrypted in order to create the bundle (PKCS12, JKS)
	// Firefly does not encrypt Private Keys. Thus, Private Key should not be decrypted in that scenario
	if pcc.PrivateKey != "" && decryptPK {

		privateKey, err := vcertutil.DecryptPrivateKey(pcc.PrivateKey, request.KeyPassword)
		if err != nil {
			// there's chance we've got a private key that is not PKCS8
			zap.L().Debug("PKCS8 decrypt failed for opening Private Key. Trying legacy decrypt")
			privKey, err := getPrivateKey(pcc.PrivateKey, request.KeyPassword)
			if err != nil {
				return nil, err
			}

			var privKeyBlock *pem.Block

			privKeyD := privKey.(crypto.Signer)
			privKeyBlock, err = certificate.GetPrivateKeyPEMBock(privKeyD, util.LegacyPem)
			if err != nil {
				return nil, err
			}
			privEncodedPEM := pem.EncodeToMemory(privKeyBlock)
			privKeyPEMString := string(privEncodedPEM)
			pcc.PrivateKey = privKeyPEMString
			privateKey = privKeyPEMString
		}
		pcc.PrivateKey = privateKey
		zap.L().Debug("successfully decrypted Private Key")
	}

	return &pcc, nil
}

func loadPEMCertificate(certFile string) (*x509.Certificate, error) {
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	return parsePEMCertificate(certData)
}

func parsePEMCertificate(certData []byte) (*x509.Certificate, error) {
	p, _ := pem.Decode(certData)
	if p == nil {
		return nil, fmt.Errorf("could not decode PEM data")
	}
	if p.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate data does not contain a certificate")
	}

	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate to X509 object: %w", err)
	}

	return cert, nil
}

func needRenewal(cert *x509.Certificate, renewBefore string) bool {
	// if duration is 0 anything, then return false, auto-renewal is disabled
	if renewBefore == "0" || strings.ToLower(renewBefore) == "disabled" {
		zap.L().Warn("certificate expiring soon but automatic renewal disabled",
			zap.String("certificate", cert.Subject.CommonName),
			zap.String("expirationDate", cert.NotAfter.String()))
		return false
	}

	timePostfix := renewBefore[len(renewBefore)-1:]

	renew := renewBefore[:len(renewBefore)-1]
	renewValue, err := strconv.ParseInt(renew, 10, 32)
	if err != nil {
		zap.L().Error("could not parse renewBefore value. Using default value [10%] instead",
			zap.String("renewBefore", renewBefore), zap.Error(err))
		// TODO: use real global default duration
		timePostfix = "%"
		renewValue = 10
	}

	// if duration is 0 anything, then return false, auto-renewal is disabled
	if renewValue == 0 {
		zap.L().Warn("certificate expiring soon but automatic renewal disabled",
			zap.String("certificate", cert.Subject.CommonName),
			zap.String("expirationDate", cert.NotAfter.String()))
		return false
	}

	// Cert expired, renew
	if cert.NotAfter.Before(time.Now()) {
		zap.L().Debug("certificate is expired", zap.String("certificate", cert.Subject.CommonName))
		return true
	}

	var timeToRenew time.Time

	switch timePostfix {
	case "d":
		// operation happens in integers to avoid issues with linter and time.Duration struct
		ns := DayDuration.Nanoseconds()
		renewDuration := time.Duration(ns * renewValue)
		timeToRenew = cert.NotAfter.Add(-renewDuration)
	case "h":
		ns := time.Hour.Nanoseconds()
		renewDuration := time.Duration(ns * renewValue)
		timeToRenew = cert.NotAfter.Add(-renewDuration)
	case "%":
		// Total # of ns in the whole certificate lifetime
		nsCertValidity := cert.NotAfter.Sub(cert.NotBefore).Nanoseconds()

		// if 10%, then renew when 90% of the validity time has elapsed
		pct := float64(renewValue) / 100
		renewDuration := time.Duration(float64(nsCertValidity) * pct)
		timeToRenew = cert.NotAfter.Add(-renewDuration)
	default:
		zap.L().Warn("unknown duration postfix. Valid postfixes are: d (Days) and h (Hours): Using default [10%]",
			zap.String("postfix", timePostfix))
		// Total # of ns in the whole certificate lifetime
		nsCertValidity := cert.NotAfter.Sub(cert.NotBefore).Nanoseconds()

		// TODO: Respect global DefaultRenewal
		renewDuration := time.Duration(float64(nsCertValidity) * float64(0.10))
		timeToRenew = cert.NotAfter.Add(-renewDuration)
	}

	// Check certificate renew window
	//Time now + renew window is bigger than cert expiration day? Then renew
	if time.Now().After(timeToRenew) {
		zap.L().Debug("certificate in renew window", zap.String("certificate", cert.Subject.CommonName))
		return true
	}

	zap.L().Info(fmt.Sprintf("cert expires on %s and will auto-renew on %s", cert.NotAfter, timeToRenew),
		zap.String("expirationDate", cert.NotAfter.String()), zap.String("renewDate", timeToRenew.String()))
	return false
}

// CreateX509Cert takes a PEMCollection and creates an x509.Certificate object from it
// Could also add the x509.Certificate object directly to the PEM collection in the original constructor
func CreateX509Cert(pcc *certificate.PEMCollection, certReq *certificate.Request, decryptPK bool) (*Certificate, *certificate.PEMCollection, error) {
	preparedPcc, err := prepareCertificateForBundle(*certReq, *pcc, decryptPK)

	if err != nil {
		return nil, nil, fmt.Errorf("could not prepare certificate and key: %w", err)
	}

	certBytes := []byte(pcc.Certificate)
	x509Cert, err := parsePEMCertificate(certBytes)

	if err != nil {
		return nil, preparedPcc, err
	}
	thumbprint := sha1.Sum(x509Cert.Raw)
	hexThumbprint := hex.EncodeToString(thumbprint[:])

	cert := Certificate{*x509Cert, hexThumbprint}

	return &cert, preparedPcc, nil
}
