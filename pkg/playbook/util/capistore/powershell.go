//go:build windows

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

package capistore

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

var (
	//go:embed embedded/install-cert.ps1
	installCertScript string
	//go:embed embedded/retrieve-cert.ps1
	retrieveCertScript string
)

// PowerShell represents the powershell program in Windows. It is used to execute any script on it
type PowerShell struct {
	powerShell string
}

// NewPowerShell creates new session
func NewPowerShell() *PowerShell {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		zap.L().Fatal("could not find powershell path", zap.Error(err))
	}
	return &PowerShell{
		powerShell: ps,
	}
}

// InstallCertificateToCAPI takes a config object  and uses it to install a new certificate in the local machine CAPI store
func (ps PowerShell) InstallCertificateToCAPI(config InstallationConfig) error {
	pfxPath := fmt.Sprintf("%s\\%s", os.TempDir(), uuid.NewString())

	// verify friendly name doesn't have command injection
	err := containsInjectableData(config.FriendlyName)
	if err != nil {
		m := "failed to install certificate because of invalid characters in friendlyName"
		zap.L().Error(m)
		return errors.WithMessagef(err, m)
	}

	err = os.WriteFile(pfxPath, config.PFX, 0600)
	if err != nil {
		zap.L().Error("could not create certificate temp file", zap.Error(err))
		return err
	}

	defer func() {
		if delErr := os.RemoveAll(pfxPath); delErr != nil {
			// Failing to delete a file containing a private key should be considered an error
			zap.L().Error("failed to delete temporary certificate file", zap.Error(delErr))
		}
	}()

	params := map[string]string{
		"certPath":        pfxPath,
		"friendlyName":    config.FriendlyName,
		"isNonExportable": psBool(config.IsNonExportable),
		"password":        config.Password,
		"storeName":       config.StoreName,
		"storeLocation":   config.StoreLocation,
	}

	stdout, err := ps.executeScript(installCertScript, "install-cert", params)
	if err != nil {
		m := "failed to install certificate into CAPI"
		zap.L().Error(m, zap.String("stdout", stdout), zap.Error(err))
		return errors.WithMessagef(err, "%s, stdout: '%s'", m, stdout)
	}

	return err
}

// RetrieveCertificateFromCAPI looks for a certificate in the CAPI store config.CertStore that matches the given config.FriendlyName.
// If found, it returns the certificate in PEM format as a string
func (ps PowerShell) RetrieveCertificateFromCAPI(config InstallationConfig) (string, error) {
	zap.L().Info("retrieving certificate from CAPI Store", zap.String("friendlyName", config.FriendlyName))

	// verify friendly name doesn't have command injection
	err := containsInjectableData(config.FriendlyName)
	if err != nil {
		m := "failed to retrieve certificate because of invalid characters in friendlyName"
		zap.L().Error(m)
		return "", errors.WithMessagef(err, m)
	}

	params := map[string]string{
		"friendlyName":  config.FriendlyName,
		"storeName":     config.StoreName,
		"storeLocation": config.StoreLocation,
	}

	stdout, err := ps.executeScript(retrieveCertScript, "retrieve-cert", params)
	if err != nil {
		m := "failed to install certificate into CAPI"
		zap.L().Error(m, zap.String("stdout", stdout), zap.Error(err))
		return "", errors.WithMessagef(err, "%s, stdout: '%s'", m, stdout)
	}

	//Certificate not found, return empty string
	notFound := fmt.Sprintf("certificate not found: %s", config.FriendlyName)
	if strings.Contains(stdout, notFound) {
		return "", nil
	}

	return stdout, nil
}

// ExecuteScript runs the specified powershell script function found within the script.
// String parameters can be specified as named arguments to the function.
// Parameters have a limited size, large parameters should be first read from disk to avoid command size limits.
func (ps PowerShell) executeScript(script, functionName string, parameters map[string]string) (string, error) {
	scriptFile := fmt.Sprintf("venafi-winrm-execute-%s.ps1", uuid.NewString())

	scriptPath := fmt.Sprintf("%s\\%s", os.TempDir(), scriptFile)

	err := copyScript(script, scriptPath)
	if err != nil {
		m := "failed to copy script"
		zap.L().Error(m)
		return "", errors.WithMessagef(err, m)
	}
	defer func() {
		if removeErr := os.RemoveAll(scriptPath); removeErr != nil {
			zap.L().Warn("failed to remove powershell script from host", zap.Error(removeErr))
		}
	}()

	stdout, err := ps.runScript(scriptPath, functionName, parameters)
	if err != nil {
		m := "failed to run script function"
		zap.L().Error(m, zap.String("functionName", functionName), zap.String("stdout", stdout), zap.Error(err))
		return "", errors.WithMessagef(err, "%s %q", m, functionName)
	}

	return stdout, nil
}

func (ps PowerShell) runScript(scriptPath, functionName string, parameters map[string]string) (string, error) {

	builder := strings.Builder{}
	builder.WriteString(fmt.Sprintf("powershell -command \". %s %s", scriptPath, functionName))
	for paramName, value := range parameters {
		builder.WriteString(fmt.Sprintf(" -%s %s", paramName, quoteIfNeeded(value)))
	}
	builder.WriteString("\"")

	script := builder.String()

	cmd := exec.Command(ps.powerShell, script)
	var stdOut, stdError bytes.Buffer
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdError
	err := cmd.Run()

	errString := "failed to run script file"
	if len(stdError.String()) != 0 {
		zap.L().Error(errString, zap.String("stderr", stdError.String()))
		return "", fmt.Errorf("%s: %s", errString, stdError.String())
	}

	if err != nil {
		zap.L().Error(errString, zap.Error(err))
		return "", fmt.Errorf("%s: %w", errString, err)
	}

	return stdOut.String(), nil
}
