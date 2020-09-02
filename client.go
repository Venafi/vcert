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
	"crypto/x509"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/cloud"
	"github.com/Venafi/vcert/v4/pkg/venafi/fake"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp"
	"github.com/Venafi/vcert/v4/pkg/verror"
	"log"
)

// NewClient returns a connector for either Trust Protection Platform (TPP) or Venafi Cloud based on provided configuration.
// Config should have Credentials compatible with the selected ConnectorType.
// Returned connector is a concurrency-safe interface to TPP or Venafi Cloud that can be reused without restriction.
// Connector can also be of type "fake" for local tests, which doesn`t connect to any backend and all certificates enroll locally.
func (cfg *Config) NewClient() (connector endpoint.Connector, err error) {
	var connectionTrustBundle *x509.CertPool

	if cfg.ConnectionTrust != "" {
		log.Println("You specified a trust bundle.")
		connectionTrustBundle = x509.NewCertPool()
		if !connectionTrustBundle.AppendCertsFromPEM([]byte(cfg.ConnectionTrust)) {
			return nil, fmt.Errorf("%w: failed to parse PEM trust bundle", verror.UserDataError)
		}
	}

	switch cfg.ConnectorType {
	case endpoint.ConnectorTypeCloud:
		connector, err = cloud.NewConnector(cfg.BaseUrl, cfg.Zone, cfg.LogVerbose, connectionTrustBundle)
	case endpoint.ConnectorTypeTPP:
		connector, err = tpp.NewConnector(cfg.BaseUrl, cfg.Zone, cfg.LogVerbose, connectionTrustBundle)
	case endpoint.ConnectorTypeFake:
		connector = fake.NewConnector(cfg.LogVerbose, connectionTrustBundle)
	default:
		err = fmt.Errorf("%w: ConnectorType is not defined", verror.UserDataError)
	}
	if err != nil {
		return
	}

	connector.SetZone(cfg.Zone)
	connector.SetHTTPClient(cfg.Client)

	err = connector.Authenticate(cfg.Credentials)
	return
}

// NewClient returns a connector for either Trust Protection Platform (TPP) or Venafi Cloud based on provided configuration.
// Config should have Credentials compatible with the selected ConnectorType.
// Returned connector is a concurrency-safe interface to TPP or Venafi Cloud that can be reused without restriction.
// Connector can also be of type "fake" for local tests, which doesn`t connect to any backend and all certificates enroll locally.
func NewClient(cfg *Config) (endpoint.Connector, error) {
	return cfg.NewClient()
}
