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

package vcert

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"
)

func init() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

func print(a interface{}) {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Println(string(b))
}

func TestNewClient(t *testing.T) {
	var haltIf = func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}

	var cfg = &Config{
		ConnectorType: endpoint.ConnectorTypeFake,
	}

	c, err := NewClient(cfg)
	haltIf(err)

	req := &certificate.Request{
		Subject: pkix.Name{
			CommonName:   "client.venafi.example.com",
			Organization: []string{"Venafi.com"}, OrganizationalUnit: []string{"Integration Team"}},
		DNSNames: []string{"www.client.venafi.example.com", "ww1.client.venafi.example.com"},
	}

	err = c.GenerateRequest(nil, req)
	haltIf(err)
	print(req)

	id, err := c.RequestCertificate(req, "")
	haltIf(err)
	print(id)

	req.Timeout = 180 * time.Second
	certs, err := c.RetrieveCertificate(req)
	haltIf(err)
	print(certs)
}

func TestNewClientWithFileConfig(t *testing.T) {
	var haltIf = func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}

	tmpfile, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	err = ioutil.WriteFile(tmpfile.Name(), []byte("test_mode = true"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	var cfg = &Config{
		ConfigFile: tmpfile.Name(),
	}

	err = cfg.LoadFromFile()
	if err != nil {
		t.Fatal(err)
	}

	c, err := NewClient(cfg)
	haltIf(err)

	req := &certificate.Request{
		Subject: pkix.Name{
			CommonName:   "client.venafi.example.com",
			Organization: []string{"Venafi.com"}, OrganizationalUnit: []string{"Integration Team"}},
		DNSNames: []string{"www.client.venafi.example.com", "ww1.client.venafi.example.com"},
	}

	err = c.GenerateRequest(nil, req)
	haltIf(err)
	print(req)

	id, err := c.RequestCertificate(req, "")
	haltIf(err)
	print(id)

	req.Timeout = 180 * time.Second
	certs, err := c.RetrieveCertificate(req)
	haltIf(err)
	print(certs)
}
