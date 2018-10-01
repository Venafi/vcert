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

package main

import (
	"fmt"
	"github.com/Venafi/vcert"
)

const UtilityName string = "Venafi Certificate Utility"
const UtilityShortName string = "vCert"

var (
	showVersion bool
)

func printVersion() {
	fmt.Printf("%s\n", GetFormattedVersionString())
}

//GetFormattedVersionString gets a friendly printable string to represent the version
func GetFormattedVersionString() string {
	return vcert.GetFormattedVersionString()
}
