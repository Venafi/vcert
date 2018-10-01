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
	"os"
)

func setupRegistrationFlags() {
	registerFlags.StringVar(&regParams.cloudURL, "venafi-saas-url", "", "")
	registerFlags.StringVar(&regParams.email, "email", "", "")
	registerFlags.BoolVar(&regParams.verbose, "verbose", false, "")
	registerFlags.BoolVar(&regParams.insecure, "insecure", false, "")

	registerFlags.Usage = func() {
		fmt.Printf("%s\n", vcert.GetFormattedVersionString())
		showRegisterUsage()
	}
}

func showRegisterUsage() {
	fmt.Printf("Registration Usage:\n")
	fmt.Printf("  %s register <Required>\n", os.Args[0])
	fmt.Printf("  %s register -email <email@abccorp.com>\n", os.Args[0])
	fmt.Println()
	fmt.Printf("Required:\n")
	fmt.Println("  -email")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Specify the corporate email address to register with and receive additional instructions about activation. Example: -email email@abccorp.com"))
	fmt.Println("  -h")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to show the help text."))
	fmt.Println()
}
