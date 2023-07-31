//go:build !windows

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

package installer

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain"
)

// GetInstaller returns a proper installer according to the type defined in inst
func GetInstaller(inst domain.Installation) Installer {
	switch inst.Type {
	case domain.FormatJKS:
		return NewJKSInstaller(inst)
	case domain.FormatPEM:
		return NewPEMInstaller(inst)
	case domain.FormatPKCS12:
		return NewPKCS12Installer(inst)
	default:
		zap.L().Fatal(fmt.Sprintf("Runner not found for installation type: %s", inst.Type.String()))
		return nil
	}
}
