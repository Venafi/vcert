/*
 * Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
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
	"strconv"
	"time"

	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/urfave/cli/v2"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/certificate"
)

var (
	commandSshPickup = &cli.Command{
		Before:    runBeforeCommand,
		Name:      commandSshPickupName,
		Flags:     sshPickupFlags,
		Action:    doCommandSSHPickup,
		Usage:     "To retrieve an SSH Certificate from CyberArk SSH Manager for Machines",
		UsageText: `vcert sshpickup -u https://sshmf.example.com -t <CyberArk SSH Manager for Machines access token> --pickup-id <ssh cert DN>`,
	}

	commandSshEnroll = &cli.Command{
		Before:    runBeforeCommand,
		Name:      commandSshEnrollName,
		Flags:     sshEnrollFlags,
		Action:    doCommandSSHEnroll,
		Usage:     "To enroll an SSH Certificate to CyberArk SSH Manager for Machines",
		UsageText: `vcert sshenroll -u https://sshmf.example.com -t <CyberArk SSH Manager for Machines access token> --template <val> --id <val> --principal bob --principal alice --valid-hours 1`,
	}

	commandSshGetConfig = &cli.Command{
		Before:    runBeforeCommand,
		Name:      commandSshGetConfigName,
		Flags:     sshGetConfigFlags,
		Action:    doCommandSSHGetConfig,
		Usage:     "To get the SSH CA public key and default principals from CyberArk SSH Manager for Machines",
		UsageText: `vcert sshgetconfig -u https://sshmf.example.com -t <CyberArk SSH Manager for Machines access token> --template <val>`,
	}
)

func doCommandSSHPickup(c *cli.Context) error {

	err := validateSshRetrieveFlags(c.Command.Name)

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

	connector, err := vcert.NewClient(&cfg) // Everything else requires an endpoint connection
	if err != nil {
		logf("Unable to connect to %s: %s", cfg.ConnectorType, err)
	} else {
		logf("Successfully connected to %s", cfg.ConnectorType)
	}

	var req certificate.SshCertRequest

	req = buildSSHCertificateRequest(req, &flags)

	req.Timeout = time.Duration(10) * time.Second
	data, err := connector.RetrieveSSHCertificate(&req)

	if err != nil {
		return fmt.Errorf("failed to retrieve certificate: %s", err)
	}
	logf("Successfully retrieved request for %s", data.DN)

	printSshMetadata(data)
	privateKeyS := data.PrivateKeyData
	if privateKeyS != "" {
		privateKeyS = AddLineEnding(privateKeyS)
	}

	// If --file is not set, use Key ID as filename
	privateKeyFileName := flags.sshFileCertEnroll
	if privateKeyFileName == "" {
		privateKeyFileName = data.CertificateDetails.KeyID
	}

	// Check if the files already exist and prompt the user to overwrite
	if !flags.noPrompt {
		err = validateExistingFile(privateKeyFileName)
		if err != nil {
			return err
		}
	}

	err = writeSshFiles(privateKeyFileName, []byte(privateKeyS), []byte(data.PublicKeyData), []byte(data.CertificateData))
	if err != nil {
		return err
	}

	return nil
}

func doCommandSSHEnroll(c *cli.Context) error {

	err := validateSshEnrollFlags(c.Command.Name)

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

	connector, err := vcert.NewClient(&cfg)

	if err != nil {
		logf("Unable to build connector for %s: %s", cfg.ConnectorType, err)
	} else {
		if flags.verbose {
			logf("Successfully built connector for %s", cfg.ConnectorType)
		}
	}

	err = connector.Ping()

	if err != nil {
		logf("Unable to connect to %s: %s", cfg.ConnectorType, err)
	} else {
		if flags.verbose {
			logf("Successfully connected to %s", cfg.ConnectorType)
		}
	}

	var req = &certificate.SshCertRequest{}

	req = fillSSHCertificateRequest(req, &flags)

	if flags.sshCertKeyPassphrase != "" {
		flags.keyPassword = flags.sshCertKeyPassphrase
	}

	var privateKey, publicKey []byte
	sPubKey := ""
	//support for local generated keypair or provided public key
	if flags.sshCertPubKey == SshCertPubKeyLocal {

		keySize := flags.sshCertKeySize
		if keySize <= 0 {
			keySize = 3072
		}

		privateKey, publicKey, err = util.GenerateSshKeyPair(keySize, flags.keyPassword, flags.sshCertKeyId, flags.format)

		if err != nil {
			return err
		}

		sPubKey = string(publicKey)
		req.PublicKeyData = sPubKey
	}

	if isPubKeyInFile() {
		pubKeyS, err := getSshPubKeyFromFile()

		if err != nil {
			return err
		}

		if pubKeyS == "" {
			return fmt.Errorf("specified public key in %s is empty", flags.sshCertPubKey)
		}

		req.PublicKeyData = pubKeyS
	}

	req.Timeout = time.Duration(flags.timeout) * time.Second
	data, err := connector.RequestSSHCertificate(req)

	if err != nil {
		return err
	}

	// 'Rejected' status is handled in the connector
	if (data.ProcessingDetails.Status == "Pending Issue") || (data.ProcessingDetails.Status == "Issued" && data.CertificateData == "") {
		logf("SSH certificate was successfully requested. Retrieving the certificate data.")

		flags.pickupID = data.DN
		retReq := certificate.SshCertRequest{
			PickupID:                  flags.pickupID,
			IncludeCertificateDetails: true,
		}
		if flags.keyPassword != "" {
			retReq.PrivateKeyPassphrase = flags.keyPassword
		}

		retReq.Timeout = time.Duration(10) * time.Second
		data, err = connector.RetrieveSSHCertificate(&retReq)
		if err != nil {
			return fmt.Errorf("Failed to retrieve SSH certificate '%s'. Error: %s", flags.pickupID, err)
		}
	} else {
		logf("Successfully issued SSH certificate with Key ID '%s'", data.CertificateDetails.KeyID)
	}

	//this case is when the keypair is local generated
	if data.PrivateKeyData == "" {
		data.PrivateKeyData = string(privateKey)
	}
	if sPubKey != "" {
		data.PublicKeyData = sPubKey
	}

	printSshMetadata(data)
	privateKeyS := data.PrivateKeyData
	if isServiceGenerated() {
		privateKeyS = AddLineEnding(privateKeyS)
	}

	privateKeyFileName := flags.sshFileCertEnroll
	if privateKeyFileName == "" {
		privateKeyFileName = data.CertificateDetails.KeyID
	}

	// Check if the files already exist and prompt the user to overwrite
	if !flags.noPrompt {
		err = validateExistingFile(privateKeyFileName)
		if err != nil {
			return err
		}
	}

	err = writeSshFiles(privateKeyFileName, []byte(privateKeyS), []byte(data.PublicKeyData), []byte(data.CertificateData))
	if err != nil {
		return err
	}

	return nil
}

func doCommandSSHGetConfig(c *cli.Context) error {

	err := validateGetSshConfigFlags(c.Command.Name)

	if err != nil {
		return err
	}

	err = setTLSConfig()
	if err != nil {
		return err
	}

	cfg, err := buildConfig(c, &flags)
	if err != nil {
		return fmt.Errorf("failed to build vcert config: %s", err)
	}

	connector, err := vcert.NewClient(&cfg)

	if err != nil {
		strErr := (err).Error()
		if strErr != "vcert error: your data contains problems: auth error: failed to authenticate: can't determine valid credentials set" {
			logf("Unable to build connector for %s: %s", cfg.ConnectorType, err)
		} else {
			logf("Successfully built connector for %s", cfg.ConnectorType)
		}
	} else {
		logf("Successfully built connector for %s", cfg.ConnectorType)
	}

	err = connector.Ping()

	if err != nil {
		logf("Unable to connect to %s: %s", cfg.ConnectorType, err)
	} else {
		logf("Successfully connected to %s", cfg.ConnectorType)
	}

	req := &certificate.SshCaTemplateRequest{}
	if flags.sshCertTemplate != "" {
		req.Template = flags.sshCertTemplate
	}
	if flags.sshCertGuid != "" {
		req.Guid = flags.sshCertGuid
	}

	conf, err := connector.RetrieveSshConfig(req)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("CA public key:")
	fmt.Println(conf.CaPublicKey)

	if len(conf.Principals) > 0 {
		fmt.Println()
		fmt.Println("Principals:")
		for _, v := range conf.Principals {
			fmt.Println(v)
		}
	}

	if flags.sshFileGetConfig != "" {
		// Check if the file already exists and prompt the user to overwrite
		if !flags.noPrompt {
			err = validateExistingFile(flags.sshFileGetConfig)
			if err != nil {
				return err
			}
		}

		err = writeToFile([]byte(conf.CaPublicKey), flags.sshFileGetConfig, 0600)
		if err != nil {
			return err
		}
	}

	return nil
}

func buildSSHCertificateRequest(r certificate.SshCertRequest, cf *commandFlags) certificate.SshCertRequest {

	if cf.sshCertKeyPassphrase != "" {
		cf.keyPassword = cf.sshCertKeyPassphrase
	}

	if cf.sshCertPickupId != "" {
		r.PickupID = cf.sshCertPickupId
	}

	if cf.sshCertGuid != "" {
		r.Guid = cf.sshCertGuid
	}

	if cf.keyPassword != "" {
		r.PrivateKeyPassphrase = cf.keyPassword
	}

	r.IncludeCertificateDetails = true

	return r
}

func fillSSHCertificateRequest(req *certificate.SshCertRequest, cf *commandFlags) *certificate.SshCertRequest {

	if cf.sshCertTemplate != "" {
		req.Template = cf.sshCertTemplate
	}

	if cf.sshCertKeyId != "" {
		req.KeyId = cf.sshCertKeyId
	}

	if cf.sshCertObjectName != "" {
		req.ObjectName = cf.sshCertObjectName
	}

	if cf.sshCertValidHours > 0 {
		req.ValidityPeriod = strconv.Itoa(cf.sshCertValidHours) + "h"
	}

	if cf.sshCertFolder != "" {
		req.PolicyDN = cf.sshCertFolder
	}

	if len(cf.sshCertDestAddrs) > 0 {
		req.DestinationAddresses = cf.sshCertDestAddrs
	}

	if len(cf.sshCertPrincipal) > 0 {
		req.Principals = cf.sshCertPrincipal
	}

	if len(cf.sshCertExtension) > 0 {
		req.Extensions = cf.sshCertExtension
	}

	if len(cf.sshCertSourceAddrs) > 0 {
		req.SourceAddresses = cf.sshCertSourceAddrs
	}

	if cf.sshCertPubKeyData != "" {
		req.PublicKeyData = cf.sshCertPubKeyData
	}

	if cf.sshCertForceCommand != "" {
		req.ForceCommand = cf.sshCertForceCommand
	}

	return req
}
