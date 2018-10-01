/*
 * Copyright 2018 Venafi, Inc.
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

package output

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"io/ioutil"
	"os"
	"software.sslmate.com/src/go-pkcs12"
	"strings"
)

type command int

const (
	commandRegister command = iota
	commandGenCSR
	commandEnroll
	commandPickup
	commandRevoke
	commandRenew
)

type Config struct {
	Command     int
	Format      string
	ChainOption certificate.ChainOption

	AllFile      string
	KeyFile      string
	CertFile     string
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
	if x509.IsEncryptedPEMBlock(p) {
		privDER, err = x509.DecryptPEMBlock(p, []byte(c.KeyPassword))
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
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(privDER)
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

		var bytes []byte
		if r.Config.Format == "pkcs12" {
			bytes, err = allFileOutput.AsPKCS12(r.Config)
			if err != nil {
				return fmt.Errorf("failed to encode pkcs12: %s", err)
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
			bytes, err := certFileOutput.Format(r.Config)
			if err != nil {
				return err // something worse than file permission problem
			} else {
				err = ioutil.WriteFile(r.Config.CertFile, bytes, 0600)
				errors = append(errors, err)
			}
		} else {
			stdOut.Certificate = r.Pcc.Certificate
		}
		if r.Config.KeyFile != "" && r.Pcc.PrivateKey != "" {
			err = ioutil.WriteFile(r.Config.KeyFile, []byte(r.format(r.Pcc.PrivateKey)), 0600)
			errors = append(errors, err)
		} else {
			stdOut.PrivateKey = r.Pcc.PrivateKey
		}
		if r.Config.ChainFile != "" && len(r.Pcc.Chain) > 0 {
			err = ioutil.WriteFile(r.Config.ChainFile, []byte(r.formatChain(r.Pcc.Chain)), 0600)
			errors = append(errors, err)
		} else {
			stdOut.Chain = r.Pcc.Chain
		}
	}
	// PickupId is special -- it wasn't supposed to be written to -file
	if r.Config.Command == int(commandEnroll) || r.Config.Command == int(commandRenew) {
		if r.Config.PickupIdFile != "" && r.PickupId != "" {
			err = ioutil.WriteFile(r.Config.PickupIdFile, []byte(r.format(r.PickupId)+"\n"), 0600)
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
