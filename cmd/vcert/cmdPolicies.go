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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/policy"
)

var (
	commandCreatePolicy = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandCreatePolicyName,
		Flags:  createPolicyFlags,
		Action: doCommandCreatePolicy,
		Usage:  "To apply a certificate policy specification to a zone",
		UsageText: ` vcert setpolicy <Required CyberArk Certificate Manager, SaaS -OR- CyberArk Certificate Manager, Self-Hosted> <Options>
        vcert setpolicy -u https://cmsh.example.com -t <CyberArk Certificate Manager, Self-Hosted access token> -z "<policy folder DN>" --file /path-to/policy.spec
		vcert setpolicy -p vcp -t <CyberArk Certificate Manager, SaaS access token> -z "<app name>\<CIT alias>" --file /path-to/policy.spec`,
	}

	commandGetPolicy = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandGetePolicyName,
		Flags:  getPolicyFlags,
		Action: doCommandGetPolicy,
		Usage:  "To retrieve the certificate policy of a zone",
		UsageText: ` vcert getpolicy <Required CyberArk Certificate Manager, SaaS -OR- CyberArk Certificate Manager, Self-Hosted> <Options>
        vcert getpolicy -u https://cmsh.example.com -t <CyberArk Certificate Manager, Self-Hosted access token> -z "<policy folder DN>"
		vcert getpolicy -p vcp -t <CyberArk Certificate Manager, SaaS access token> -z "<app name>\<CIT alias>"`,
	}
)

func doCommandCreatePolicy(c *cli.Context) error {

	err := validateSetPolicyFlags(c.Command.Name)

	if err != nil {
		return err
	}

	err = setTLSConfig()
	if err != nil {
		return err
	}

	policyName := flags.policyName
	policySpecLocation := flags.policySpecLocation

	logf("Loading policy specification from %s", policySpecLocation)

	file, bytes, err := policy.GetFileAndBytes(policySpecLocation)

	if err != nil {
		return err
	}

	if flags.verbose {
		logf("Policy specification file was successfully opened")
	}

	fileExt := policy.GetFileType(policySpecLocation)
	fileExt = strings.ToLower(fileExt)

	if flags.verifyPolicyConfig {
		err = policy.VerifyPolicySpec(bytes, fileExt)
		if err != nil {
			err = fmt.Errorf("policy specification file is not valid: %s", err)
			return err
		} else {
			logf("policy specification %s is valid", policySpecLocation)
			return nil
		}
	}

	//based on the extension call the appropriate method to feed the policySpecification
	//structure.
	var policySpecification policy.PolicySpecification
	if fileExt == policy.JsonExtension {
		err = json.Unmarshal(bytes, &policySpecification)
		if err != nil {
			return err
		}
	} else if fileExt == policy.YamlExtension {
		err = yaml.Unmarshal(bytes, &policySpecification)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("the specified file is not supported")
	}

	cfg, err := buildConfig(c, &flags)

	if err != nil {
		return fmt.Errorf("failed to build vcert config: %s", err)
	}
	connector, err := vcert.NewClient(&cfg)

	if err != nil {
		return err
	}

	_, err = connector.SetPolicy(policyName, &policySpecification)

	defer file.Close()

	return err
}

func doCommandGetPolicy(c *cli.Context) error {

	err := validateGetPolicyFlags(c.Command.Name)

	if err != nil {
		return err
	}

	err = setTLSConfig()
	if err != nil {
		return err
	}

	policyName := flags.policyName

	policySpecLocation := flags.policySpecLocation

	var ps *policy.PolicySpecification

	if !flags.policyConfigStarter {

		cfg, err := buildConfig(c, &flags)
		if err != nil {
			return fmt.Errorf("failed to build vcert config: %s", err)
		}

		connector, err := vcert.NewClient(&cfg)

		if err != nil {

			return err

		}

		ps, err = connector.GetPolicy(policyName)

		if err != nil {
			return err
		}

	} else {

		ps = policy.GetPolicySpec()

	}

	var b []byte

	if policySpecLocation != "" {

		fileExt := policy.GetFileType(policySpecLocation)
		fileExt = strings.ToLower(fileExt)
		if fileExt == policy.JsonExtension {
			b, _ = json.MarshalIndent(ps, "", "  ")
			if err != nil {
				return err
			}
		} else if fileExt == policy.YamlExtension {
			b, _ = yaml.Marshal(ps)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("the specified byte is not supported")
		}

		err = os.WriteFile(policySpecLocation, b, 0600)
		if err != nil {
			return err
		}
		log.Printf("policy was written in: %s", policySpecLocation)

	} else {

		b, _ = json.MarshalIndent(ps, "", "  ")

		if err != nil {
			return err
		}
		log.Println("Policy is:")
		fmt.Println(string(b))
	}

	return nil
}
