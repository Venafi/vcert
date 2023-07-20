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

package service

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/installer"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/vcertutil"
)

// DefaultRenew represents the duration before certificate expiration in which renewal should be attempted
const (
	DefaultRenew = "10%"

	envVarThumbprint = "thumbprint"
	envVarSerial     = "serial"
	envVarBase64     = "base64"
)

// Execute takes the task and requests the certificate specified,
// then it installs it in the locations defined by the installers.
//
// Config is used to make the connection to the Venafi platform for the certificate request.
func Execute(config domain.Config, task domain.CertificateTask) []error {
	//If forceRenew is set, then no need to check the certificate status
	if config.ForceRenew {
		zap.L().Info("force-renew flag is set. All certificates will be requested/renewed regardless of status")
	} else {

		if task.RenewBefore == "" {
			// TODO: change DefaultRenew to string
			task.RenewBefore = DefaultRenew
		}

		// renewDuration := task.GetRenewDuration()
		changed := false
		// check if any installs have changed
		for _, install := range task.Installations {
			isChanged, err := installer.GetInstaller(install).Check(task.Name, task.RenewBefore, task.Request)
			if err != nil {
				return []error{fmt.Errorf("error checking for certificate %s: %w", task.Name, err)}
			}
			if isChanged {
				changed = true
			}
		}

		// Config has not changed. Do nothing
		if !changed {
			zap.L().Info(fmt.Sprintf("certificate %s in good health. No actions needed", task.Name))
			return nil
		}
		zap.L().Info(fmt.Sprintf("certificate %s needs action", task.Request.Subject.CommonName))
	}

	//Config changed or certificate needs renewal. Do request
	pcc, vRequest, err := vcertutil.EnrollCertificate(config, task.Request)
	if err != nil {
		return []error{fmt.Errorf("error requesting certificate %s: %w", task.Name, err)}
	}
	zap.L().Info(fmt.Sprintf("successfully enrolled certificate %s", task.Request.Subject.CommonName))

	x509Certificate, prepedPcc, err := installer.CreateX509Cert(pcc, vRequest)
	if err != nil {
		e := fmt.Errorf("error preparing certificate for installation: %w", err)
		zap.L().Error(e.Error())
		return []error{e}
	}
	zap.L().Info("successfully prepared certificate for installation")

	if task.SetEnvVars != nil {
		zap.L().Debug("setting environment variables")
		setEnvVars(task, x509Certificate, prepedPcc)
	}

	errorList := make([]error, 0)
	for _, installation := range task.Installations {
		e := runInstaller(task.Name, installation, vRequest, prepedPcc)
		if e != nil {
			errorList = append(errorList, e)
		}
	}
	return errorList

}

func runInstaller(taskName string, installation domain.Installation, vcertRequest *certificate.Request, prepedPcc *certificate.PEMCollection) error {
	instlr := installer.GetInstaller(installation)
	zap.L().Info(fmt.Sprintf("running Installer: %s. Location: %s", installation.Type.String(), installation.Location))

	var err error

	if installation.BackupFiles == true {
		zap.L().Info(fmt.Sprintf("backing up certificate for Installer: %s. Location: %s", installation.Type.String(), installation.Location))
		err = instlr.Backup(taskName, *vcertRequest)
		if err != nil {
			e := fmt.Errorf("error backing up certificate at location %s: %w", installation.Location, err)
			zap.L().Error(e.Error())
			return e
		}
	}

	err = instlr.Install(taskName, *vcertRequest, *prepedPcc)
	if err != nil {
		e := fmt.Errorf("error installing certificate at location %s: %w", installation.Location, err)
		zap.L().Error(e.Error())
		return e
	}
	zap.L().Info(fmt.Sprintf("successfully installed certificate at %s.", installation.Location))

	if installation.AfterAction == "" {
		zap.L().Info("no after-install actions declared")
		return nil
	}

	err = instlr.AfterInstallActions()
	if err != nil {
		e := fmt.Errorf("error running after-install actions at location %s: %w", installation.Location, err)
		zap.L().Error(e.Error())
		return e
	}
	zap.L().Info("successfully executed after-install actions")

	validationResults, err := instlr.InstallValidationActions()
	zap.L().Debug(fmt.Sprintf("install validation result is: %s", validationResults))

	if err != nil {
		e := fmt.Errorf("error running after-install actions at location %s: %w", installation.Location, err)
		zap.L().Error(e.Error())
		return e
	} else if strings.TrimSpace(validationResults) == "1" {
		zap.L().Info("installation validation actions failed")
	}
	zap.L().Info("successfully executed installation validation actions")

	return nil
}

func setEnvVars(task domain.CertificateTask, cert *installer.Certificate, prepedPcc *certificate.PEMCollection) {
	//todo case sensitivity. upper the name
	for _, envVar := range task.SetEnvVars {
		varName := ""
		varValue := ""
		switch strings.ToLower(envVar) {
		case envVarThumbprint:
			varName = fmt.Sprintf("VCERT_%s_THUMBPRINT", strings.ToUpper(task.Name))
			varValue = cert.Thumbprint
		case envVarSerial:
			varName = fmt.Sprintf("VCERT_%s_SERIAL", strings.ToUpper(task.Name))
			varValue = cert.X509cert.Subject.SerialNumber
		case envVarBase64:
			varName = fmt.Sprintf("VCERT_%s_BASE64", strings.ToUpper(task.Name))
			varValue = prepedPcc.Certificate
		default:
			zap.L().Error("environment variable not supported", zap.String("envVar", envVar))
			continue
		}

		if varValue == "" {
			zap.L().Error("environment variable value not found", zap.String("envVar", varName))
			continue
		}

		err := os.Setenv(varName, varValue)
		if err != nil {
			zap.L().Error("failed to set environment variable", zap.String("envVar", varName), zap.Error(err))
		}
	}
}
