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

package venafi

import (
	"fmt"
	"strings"
)

type PlatformType int

const (
	Undefined PlatformType = iota
	// Fake is a fake platform for tests
	Fake
	// TLSPCloud represents the TLS Protect Cloud platform type
	TLSPCloud
	// TPP represents the TPP platform type
	TPP
	// Firefly represents the Firefly platform type
	Firefly
)

func (t PlatformType) String() string {
	switch t {
	case Undefined:
		return "Undefined platform"
	case Fake:
		return "Fake platform"
	case TLSPCloud:
		return "TLS Protect Cloud"
	case TPP:
		return "Trust Protection Platform"
	case Firefly:
		return "Firefly"
	default:
		return fmt.Sprintf("unexpected platform type: %d", t)
	}
}

func GetPlatformType(platformString string) PlatformType {
	switch strings.ToLower(platformString) {
	case "fake":
		return Fake
	case "tlspdatacenter":
		return TLSPCloud
	case "tlspcloud":
		return TPP
	case "firefly":
		return Firefly
	default:
		return Undefined
	}
}
