/*
 * Copyright 2020-2024 Venafi, Inc.
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
	"fmt"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi/cloud"
	"github.com/Venafi/vcert/v5/pkg/venafi/fake"
	"github.com/Venafi/vcert/v5/pkg/venafi/firefly"
	"github.com/Venafi/vcert/v5/pkg/venafi/tpp"
)

var (
	commandGetCred = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandGetCredName,
		Flags:  getCredFlags,
		Action: doCommandCredMgmt1,
		Usage:  "To obtain a new access token for authentication",
		UsageText: ` vcert getcred --email <email address for Venafi Control Plane headless registration> [--password <password>] [--format (text|json)]
		vcert getcred -p vcp --token-url <VCP token url> --external-jwt <JWT from Identity Provider>
		
		vcert getcred -u https://tpp.example.com --username <TPP user> --password <TPP user password>
		vcert getcred -u https://tpp.example.com --p12-file <PKCS#12 client cert> --p12-password <PKCS#12 password> --trust-bundle /path-to/bundle.pem
		vcert getcred -u https://tpp.example.com -t <TPP refresh token>
		vcert getcred -u https://tpp.example.com -t <TPP refresh token> --scope <scopes and restrictions>
		vcert getcred -p tpp -u https://tpp.example.com -t <TPP refresh token>

		vcert getcred -p oidc -u https://authorization-server.com/oauth/token --username <okta user> --password <okta user password> --scope okta.behaviors.manage
		vcert getcred -p oidc -u https://authorization-server.com/oauth/token --client-id <okta client id> --client-secret <okta client secret> --scope okta.behaviors.manage`,
	}

	commandCheckCred = &cli.Command{
		Before:    runBeforeCommand,
		Name:      commandCheckCredName,
		Flags:     checkCredFlags,
		Action:    doCommandCredMgmt1,
		Usage:     "To verify whether a Trust Protection Platform access token is valid and view its attributes",
		UsageText: " vcert checkcred -u https://tpp.example.com -t <TPP access token> --trust-bundle /path-to/bundle.pem",
	}

	commandVoidCred = &cli.Command{
		Before:    runBeforeCommand,
		Name:      commandVoidCredName,
		Flags:     voidCredFlags,
		Action:    doCommandCredMgmt1,
		Usage:     "To invalidate a Trust Protection Platform access token",
		UsageText: " vcert voidcred -u https://tpp.example.com -t <TPP access token> --trust-bundle /path-to/bundle.pem",
	}
)

func doCommandCredMgmt1(c *cli.Context) error {
	err := validateCredMgmtFlags1(c.Command.Name)
	if err != nil {
		return err
	}

	err = setTLSConfig()
	if err != nil {
		return err
	}

	cfg, err := buildConfig(c, &flags)
	if err != nil {
		return fmt.Errorf("Failed to build vcert config: %s", err)
	}

	var clientP12 bool
	if flags.clientP12 != "" {
		clientP12 = true
	}

	connector, err := vcert.NewClient(&cfg, false) // Everything else requires an endpoint connection
	if err != nil {
		return fmt.Errorf("could not create connector: %s", err)
	}

	//getting the concrete connector
	vaasConnector, okCloud := connector.(*cloud.Connector)
	tppConnector, okTPP := connector.(*tpp.Connector)
	fireflyConnector, okFirefly := connector.(*firefly.Connector)
	_, okFake := connector.(*fake.Connector) //trying to cast to fake.Connector

	if !okCloud && !okTPP && !okFirefly && !okFake {
		panic("it was not possible to get a supported connector")
	}

	if okFake {
		panic("operation is not supported yet")

	}

	switch c.Command.Name {
	case commandGetCredName:
		if vaasConnector != nil {
			return getVaaSCredentials(vaasConnector, &cfg)
		}
		if tppConnector != nil {
			return getTppCredentials(tppConnector, &cfg, clientP12)
		}
		if fireflyConnector != nil {
			return getFireflyCredentials(fireflyConnector, &cfg)
		}
	case commandCheckCredName:
		//TODO: quick workaround to suppress logs when output is in JSON.
		if flags.credFormat != "json" {
			logf("Checking credentials...")
		}

		if cfg.Credentials.AccessToken != "" {
			resp, err := tppConnector.VerifyAccessToken(&endpoint.Authentication{
				AccessToken: cfg.Credentials.AccessToken,
			})
			if err != nil {
				return err
			}
			if flags.credFormat == "json" {
				if err := outputJSON(resp); err != nil {
					return err
				}
			} else {
				iso8601fmt := "2006-01-02T15:04:05Z"
				tm, _ := time.Parse(iso8601fmt, resp.AccessIssuedOn)
				accessExpires := tm.Add(time.Duration(resp.ValidFor) * time.Second).Format(iso8601fmt)
				fmt.Println("access_token_expires: ", accessExpires)
				fmt.Println("grant_expires: ", resp.Expires)
				fmt.Println("client_id: ", resp.ClientID)
				fmt.Println("scope: ", resp.Scope)
			}
		} else {
			return fmt.Errorf("Failed to determine credentials set")
		}
	case commandVoidCredName:
		if cfg.Credentials.AccessToken != "" {
			err := tppConnector.RevokeAccessToken(&endpoint.Authentication{
				AccessToken: cfg.Credentials.AccessToken,
			})
			if err != nil {
				return err
			}
			logf("Access token grant successfully revoked")
		} else {
			return fmt.Errorf("Failed to determine credentials set")
		}
	default:
		return fmt.Errorf("Unexpected credential operation %s", c.Command.Name)
	}

	return nil
}
