/*
 * Copyright 2018-2021 Venafi, Inc.
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

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/util"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/pavel-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"
)

type Config struct {
	Command     string
	Format      string
	JKSAlias    string
	JKSPassword string
	ChainOption certificate.ChainOption

	AllFile      string
	KeyFile      string
	CertFile     string
	CSRFile      string
	ChainFile    string
	PickupIdFile string

	KeyPassword string
}

type Result struct {
	Pcc      *certificate.PEMCollection
	PickupId string
	Config   *Config
}

type Output struct {
	Certificate string   `json:",omitempty"`
	CSR         string   `json:",omitempty"`
	PrivateKey  string   `json:",omitempty"`
	Chain       []string `json:",omitempty"`
	PickupId    string   `json:",omitempty"`
}

func (o *Output) AsPKCS12(c *Config) ([]byte, error) {
	if len(o.Certificate) == 0 || len(o.PrivateKey) == 0 {
		return nil, fmt.Errorf("at least certificate and private key are required")
	}
	p, _ := pem.Decode([]byte(o.Certificate))
	if p == nil || p.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate parse error(1)")
	}
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificate parse error(2)")
	}

	// chain?
	var chain_list = []*x509.Certificate{}
	for _, chain_cert := range o.Chain {
		crt, _ := pem.Decode([]byte(chain_cert))
		cert, err := x509.ParseCertificate(crt.Bytes)
		if err != nil {
			return nil, fmt.Errorf("chain certificate parse error")
		}
		chain_list = append(chain_list, cert)
	}

	// key?
	p, _ = pem.Decode([]byte(o.PrivateKey))
	if p == nil {
		return nil, fmt.Errorf("missing private key PEM")
	}
	var privDER []byte
	if util.X509IsEncryptedPEMBlock(p) {
		privDER, err = util.X509DecryptPEMBlock(p, []byte(c.KeyPassword))
		if err != nil {
			return nil, fmt.Errorf("private key PEM decryption error: %s", err)
		}
	} else {
		privDER = p.Bytes
	}
	var privKey interface{}
	switch p.Type {
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(privDER)
		if err != nil {
			privKey, err = x509.ParsePKCS8PrivateKey(privDER)
		}
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(privDER)
		if err != nil {
			privKey, err = x509.ParsePKCS8PrivateKey(privDER)
		}
	default:
		return nil, fmt.Errorf("unexpected private key PEM type: %s", p.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("private key error(3): %s", err)
	}

	bytes, err := pkcs12.Encode(rand.Reader, privKey, cert, chain_list, c.KeyPassword)
	if err != nil {
		return nil, fmt.Errorf("encode error: %s", err)
	}

	return bytes, nil
}

func (o *Output) AsJKS(c *Config) ([]byte, error) {

	var err interface{}

	if len(o.Certificate) == 0 || len(o.PrivateKey) == 0 {
		return nil, fmt.Errorf("at least certificate and private key are required")
	}

	var certificateChain []keystore.Certificate

	//getting the certificate in bytes
	p, _ := pem.Decode([]byte(o.Certificate))
	if p == nil || p.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate parse error(1)")
	}
	var certInBytes = p.Bytes

	//adding the certificates to the slice of Certificates
	certificateChain = append(certificateChain, keystore.Certificate{
		Type:    "X509",
		Content: certInBytes,
	})

	// getting each one of the certificates in the chain of certificates and adding their bytes to the chain of certificates
	for _, chainCert := range o.Chain {
		crt, _ := pem.Decode([]byte(chainCert))
		certificateChain = append(certificateChain, keystore.Certificate{
			Type:    "X509",
			Content: crt.Bytes,
		})
	}

	// getting the bytes of the PK
	p, _ = pem.Decode([]byte(o.PrivateKey))
	if p == nil {
		return nil, fmt.Errorf("missing private key PEM")
	}
	var privDER []byte

	//decrypting the PK because due the restriction that always will be requested the key password
	//to the user(--key-password or pass phrase value from prompt) for jks format then the PK always
	//will be encrypted with the key password provided
	if util.X509IsEncryptedPEMBlock(p) {
		privDER, err = util.X509DecryptPEMBlock(p, []byte(c.KeyPassword))
		if err != nil {
			return nil, fmt.Errorf("private key PEM decryption error: %s", err)
		}
	} else {
		privDER = p.Bytes
	}

	//Unmarshalling the PK
	var privKey interface{}

	switch p.Type {
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(privDER)
		if err != nil {
			privKey, err = x509.ParsePKCS8PrivateKey(privDER)
		}
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(privDER)
		if err != nil {
			privKey, err = x509.ParsePKCS8PrivateKey(privDER)
		}
	default:
		return nil, fmt.Errorf("unexpected private key PEM type: %s", p.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("private key error(3): %s", err)
	}

	//Marshalling the PK to PKCS8, which is mandatory for JKS format
	pkcs8DER, _ := x509.MarshalPKCS8PrivateKey(privKey)

	//creating a JKS
	keyStore := keystore.New()

	//creating a PK entry
	pkeIn := keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       pkcs8DER,
		CertificateChain: certificateChain,
	}

	//adding the PK entry to the JKS. Setting as keyPass the value from keyPassword(--key-password or pass phrase value)
	if err := keyStore.SetPrivateKeyEntry(c.JKSAlias, pkeIn, []byte(c.KeyPassword)); err != nil {
		return nil, fmt.Errorf("JKS private key error: %s", err)
	}

	buffer := new(bytes.Buffer)

	var storePass []byte

	//setting as storePass the value in --jks-password or the value from keyPassword( --key-password or pass phrase value)
	if c.JKSPassword != "" {
		storePass = []byte(c.JKSPassword)
	} else {
		storePass = []byte(c.KeyPassword)
	}

	//storing the JKS to the buffer
	err = keyStore.Store(buffer, storePass)
	if err != nil {
		return nil, fmt.Errorf("JKS keystore error: %s", err) //log.Fatal(err) // nolint: gocritic
	}

	return buffer.Bytes(), nil
}

func (o *Output) Format(c *Config) ([]byte, error) {
	switch strings.ToLower(c.Format) {
	case "json":
		b, err := json.Marshal(o)
		if err != nil {
			return nil, fmt.Errorf("failed to construct JSON: %s", err)
		}
		return b, nil

	default: // pem
		res := ""
		switch c.ChainOption {
		case certificate.ChainOptionRootFirst:
			res += strings.Join(o.Chain, "")
			res += o.Certificate
			res += o.PrivateKey
		case certificate.ChainOptionIgnore:
			res += o.Certificate
			res += o.PrivateKey
		default:
			res += o.Certificate
			res += o.CSR
			res += o.PrivateKey
			res += strings.Join(o.Chain, "")
		}
		if o.PickupId != "" {
			res += fmt.Sprintf("PickupID=\"%s\"\n", o.PickupId)
		}
		return []byte(res), nil
	}
}

// this formatter mirrors previous logic of writing JSON/PEM to -*-file files
func (r *Result) format(x string) string {
	if strings.ToLower(r.Config.Format) == "json" {
		b, _ := json.Marshal(x)
		return string(b)
	} else {
		return x
	}
}

func (r *Result) formatChain(xs []string) string {
	if strings.ToLower(r.Config.Format) == "json" {
		b, _ := json.Marshal(xs)
		return string(b)
	} else {
		var s string
		for _, v := range xs {
			s += v
		}
		return s
	}
}

func (r *Result) Flush() error {
	var err error
	var errors []error

	if r.Pcc == nil {
		return fmt.Errorf("couldn't construct output: certificate collection is null")
	}

	stdOut := &Output{}

	if r.Config.AllFile != "" {
		allFileOutput := &Output{}
		allFileOutput.PrivateKey = r.Pcc.PrivateKey
		allFileOutput.Certificate = r.Pcc.Certificate
		allFileOutput.Chain = r.Pcc.Chain
		allFileOutput.CSR = r.Pcc.CSR

		var bytes []byte
		if r.Config.Format == "pkcs12" {
			bytes, err = allFileOutput.AsPKCS12(r.Config)
			if err != nil {
				return fmt.Errorf("failed to encode pkcs12: %s", err)
			}
		} else if r.Config.Format == JKSFormat {
			bytes, err = allFileOutput.AsJKS(r.Config)
			if err != nil {
				return err
			}
		} else {
			bytes, err = allFileOutput.Format(r.Config)
			if err != nil {
				return err
			}
		}
		err = ioutil.WriteFile(r.Config.AllFile, bytes, 0600)
		errors = append(errors, err)
	} else {

		if r.Config.CertFile != "" && r.Pcc.Certificate != "" {
			certFileOutput := &Output{}
			certFileOutput.Certificate = r.Pcc.Certificate
			if r.Config.ChainFile == "" {
				certFileOutput.Chain = r.Pcc.Chain
			}
			err = writeFile(certFileOutput, r, r.Config.CertFile)
			errors = append(errors, err)
		} else {
			stdOut.Certificate = r.Pcc.Certificate
		}

		if r.Config.CSRFile != "" && r.Pcc.CSR != "" {
			csrFileOutput := &Output{}
			csrFileOutput.CSR = r.Pcc.CSR
			err = writeFile(csrFileOutput, r, r.Config.CSRFile)
			errors = append(errors, err)
		} else {
			stdOut.CSR = r.Pcc.CSR
		}

		if r.Config.KeyFile != "" && r.Pcc.PrivateKey != "" {
			keyFileOutput := &Output{}
			keyFileOutput.PrivateKey = r.Pcc.PrivateKey
			err = writeFile(keyFileOutput, r, r.Config.KeyFile)
			errors = append(errors, err)
		} else {
			stdOut.PrivateKey = r.Pcc.PrivateKey
		}

		if r.Config.ChainFile != "" && len(r.Pcc.Chain) > 0 {
			chainFileOutput := &Output{}
			chainFileOutput.Chain = r.Pcc.Chain
			err = writeFile(chainFileOutput, r, r.Config.ChainFile)
			errors = append(errors, err)
		} else if r.Config.CertFile == "" {
			stdOut.Chain = r.Pcc.Chain
		}
	}
	// PickupId is special -- it wasn't supposed to be written to -file
	if r.Config.Command == commandEnrollName || r.Config.Command == commandRenewName {
		if r.Config.PickupIdFile != "" && r.PickupId != "" {
			pickupFileOutput := &Output{}
			pickupFileOutput.PickupId = r.PickupId
			err = writeFile(pickupFileOutput, r, r.Config.PickupIdFile)
			errors = append(errors, err)
		} else {
			stdOut.PickupId = r.PickupId
		}
	}

	// and flush the rest to STDOUT
	bytes, err := stdOut.Format(r.Config)
	if err != nil {
		return err // something worse than file permission problem
	}
	fmt.Fprint(os.Stdout, string(bytes))

	var finalError error
	for _, e := range errors {
		if e != nil {
			if finalError == nil {
				finalError = fmt.Errorf("error(s) happened on results output stage: ")
			}
			finalError = fmt.Errorf("%s%s; ", finalError, e)
		}
	}
	return finalError
}

func writeFile(output *Output, result *Result, filePath string) (err error) {
	if output.Certificate != "" || output.PrivateKey != "" || output.CSR != "" || len(output.Chain) > 0 {
		var bytes []byte
		bytes, err = output.Format(result.Config)
		if err != nil {
			return // something worse than file permission problem
		}
		err = ioutil.WriteFile(filePath, bytes, 0600)

	} else {
		if output.PickupId != "" {
			err = ioutil.WriteFile(result.Config.PickupIdFile, []byte(result.PickupId+"\n"), 0600)
		}
	}
	return
}

func outputJSON(resp interface{}) error {
	jsonData, err := json.MarshalIndent(resp, "", "    ")
	if err == nil {
		fmt.Println(string(jsonData))
	}
	return err
}
