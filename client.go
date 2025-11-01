/*
 * Copyright 2018-2023 Venafi, Inc.
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
	"log"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi/cloud"
	"github.com/Venafi/vcert/v5/pkg/venafi/fake"
	"github.com/Venafi/vcert/v5/pkg/venafi/firefly"
	"github.com/Venafi/vcert/v5/pkg/venafi/tpp"
	"github.com/Venafi/vcert/v5/pkg/verror"
)

type newClientArgs struct {
	authenticate bool
}

// NewClient returns a connector for either CyberArk Certificate Manager, Self-Hosted or CyberArk Certificate Manager, SaaS based on provided configuration.
// Config should have Credentials compatible with the selected ConnectorType.
// Returned connector is a concurrency-safe interface to CyberArk Certificate Manager, Self-Hosted or CyberArk Certificate Manager, SaaS that can be reused without restriction.
// Connector can also be of type "fake" for local tests, which doesn't connect to any backend and all certificates enroll locally.
// The returned connector will be authenticated by default, but it's possible to pass a bool argument to indicate if it's
// desired to get the connector authenticated already or not.
func (cfg *Config) NewClient(args ...interface{}) (connector endpoint.Connector, err error) {
	return cfg.newClient(args)
}

// this function is to manage the variadic arguments
func (cfg *Config) newClient(args []interface{}) (connector endpoint.Connector, err error) {

	var clientArgs *newClientArgs
	clientArgs, err = getNewClientArguments(args)
	if err != nil {
		return nil, err
	}

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
	case endpoint.ConnectorTypeFirefly:
		connector, err = firefly.NewConnector(cfg.BaseUrl, cfg.Zone, cfg.LogVerbose, connectionTrustBundle)
	case endpoint.ConnectorTypeFake:
		connector = fake.NewConnector(cfg.LogVerbose, connectionTrustBundle)
	default:
		err = fmt.Errorf("%w: ConnectorType is not defined", verror.UserDataError)
	}
	if err != nil {
		return
	}

	if cfg.UserAgent != nil {
		connector.SetUserAgent(*cfg.UserAgent)
	}
	connector.SetZone(cfg.Zone)
	connector.SetHTTPClient(cfg.Client)

	if clientArgs.authenticate {
		err = connector.Authenticate(cfg.Credentials)
	}

	return
}

func getNewClientArguments(args []interface{}) (*newClientArgs, error) {

	if len(args) > 1 {
		return nil, fmt.Errorf("too many arguments passed. " +
			"Only a bool argument can be passed to indicate the returned Connector will be authenticated or not. " +
			"If that argument is omitted, then by default the Connector will be authenticated")
	}

	var authenticate bool
	if len(args) == 0 {
		authenticate = true
	} else {
		var ok bool
		authenticate, ok = args[0].(bool)
		if !ok {
			return nil, fmt.Errorf("only a bool argument can be passed to indicate the returned Connector " +
				"will be authenticated or not. " +
				"If that argument is omitted, then by default the Connector will be authenticated")
		}
	}

	return &newClientArgs{
		authenticate: authenticate,
	}, nil
}

// NewClient returns a connector for either CyberArk Certificate Manager, Self-Hosted or CyberArk Certificate Manager, SaaS based on provided configuration.
// Config should have Credentials compatible with the selected ConnectorType.
// Returned connector is a concurrency-safe interface to CyberArk Certificate Manager, Self-Hosted or CyberArk Certificate Manager, SaaS that can be reused without restriction.
// Connector can also be of type "fake" for local tests, which doesn't connect to any backend and all certificates enroll locally.
// The returned connector will be authenticated by default, but it's possible to pass a bool argument to indicate if it's
// desired to get the connector authenticated already or not.
func NewClient(cfg *Config, args ...interface{}) (endpoint.Connector, error) {
	return cfg.newClient(args)
}
