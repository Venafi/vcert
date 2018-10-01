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
	"flag"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"io/ioutil"
	"os"
	"strings"
)

type command int

const (
	commandRegister command = iota
	commandGenCSR
	commandEnroll
	commandPickup
	commandRevoke
	commandRenew
)

var (
	registerFlags = flag.NewFlagSet("register", flag.PanicOnError)
	regParams     commandFlags

	genCsrFlags  = flag.NewFlagSet("gencsr", flag.PanicOnError)
	genCsrParams commandFlags

	enrollFlags  = flag.NewFlagSet("enroll", flag.PanicOnError)
	enrollParams commandFlags

	pickupFlags = flag.NewFlagSet("pickup", flag.PanicOnError)
	pickParams  commandFlags

	revokeFlags  = flag.NewFlagSet("revoke", flag.PanicOnError)
	revokeParams commandFlags

	renewFlags  = flag.NewFlagSet("renew", flag.PanicOnError)
	renewParams commandFlags
)

type commandFlags struct {
	email              string
	verbose            bool
	tppURL             string
	tppUser            string
	tppPassword        string
	apiKey             string
	cloudURL           string
	zone               string
	csrOption          string
	keyType            certificate.KeyType
	keySize            int
	keyCurve           certificate.EllipticCurve
	keyPassword        string
	friendlyName       string
	commonName         string
	distinguishedName  string
	thumbprint         string
	org                string
	country            string
	state              string
	locality           string
	orgUnits           stringSlice
	dnsSans            stringSlice
	ipSans             ipSlice
	emailSans          emailSlice
	format             string
	file               string
	keyFile            string
	csrFile            string
	certFile           string
	chainFile          string
	chainOption        string
	noPrompt           bool
	pickupID           string
	trustBundle        string
	noPickup           bool
	testMode           bool
	testModeDelay      int
	revocationReason   string
	revocationNoRetire bool
	pickupIdFile       string
	timeout            int
	insecure           bool
	config             string
	profile            string
}

func createFromCommandFlags(co command) *commandFlags {
	var f commandFlags

	switch co {
	case commandRegister:
		f = regParams
	case commandGenCSR:
		f = genCsrParams
	case commandEnroll:
		f = enrollParams
	case commandPickup:
		f = pickParams
	case commandRevoke:
		f = revokeParams
	case commandRenew:
		f = renewParams
	}

	return &f
}

func validateFlags(c command) error {
	switch c {
	case commandRegister:

	case commandGenCSR:
		return validateGenerateFlags()
	case commandEnroll:
		return validateEnrollmentFlags()
	case commandPickup:
		return validatePickupFlags()
	case commandRevoke:
		return validateRevokeFlags()
	case commandRenew:
		return validateRenewFlags()
	}

	return nil
}

func parseArgs() (co command, cf *commandFlags, err error) {

	if len(os.Args) <= 1 {
		showvcertUsage()
		exit(0)
	}

	switch strings.ToLower(os.Args[1]) {
	case "register":
		co = commandRegister
		err = registerFlags.Parse(os.Args[2:])
		if err != nil {
			logger.Panicf("%s", err)
		}
	case "gencsr":
		co = commandGenCSR
		err = genCsrFlags.Parse(os.Args[2:])
		if err != nil {
			logger.Panicf("%s", err)
		}
	case "enroll":
		co = commandEnroll
		err = enrollFlags.Parse(os.Args[2:])
		if err != nil {
			fmt.Printf("%s", err)
			logger.Panicf("%s", err)
		}
	case "pickup":
		co = commandPickup
		err = pickupFlags.Parse(os.Args[2:])
		if err != nil {
			logger.Panicf("%s", err)
		}
	case "revoke":
		co = commandRevoke
		err = revokeFlags.Parse(os.Args[2:])
		if err != nil {
			logger.Panicf("%s", err)
		}
	case "renew":
		co = commandRenew
		err = renewFlags.Parse(os.Args[2:])
		if err != nil {
			logger.Panicf("%s", err)
		}
	case "-v", "--v", "-version", "version":
		printVersion()
		exit(0)

	default:
		showvcertUsage()
		exit(0)
	}

	err = validateFlags(co)
	if err != nil {
		logger.Panicf("%s", err)
	}
	cf = createFromCommandFlags(co)

	if 0 == strings.Index(cf.distinguishedName, "file:") {
		fileName := cf.distinguishedName[5:]
		bytes, err := ioutil.ReadFile(fileName)
		if err != nil {
			logger.Panicf("Failed to read Certificate DN: %s", err)
		}
		cf.distinguishedName = strings.TrimSpace(string(bytes))
	}

	if 0 == strings.Index(cf.thumbprint, "file:") {
		certFileName := cf.thumbprint[5:]
		cf.thumbprint, err = readThumbprintFromFile(certFileName)
		if err != nil {
			logger.Panicf("Failed to read certificate fingerprint: %s", err)
		}
	}

	if cf.format != "" {
		formats := map[string]bool{
			"pem":    true,
			"json":   true,
			"pkcs12": true,
		}

		if _, ok := formats[cf.format]; !ok {
			logger.Panicf("Unexpected output format: %s", cf.format)
		}
	}

	return co, cf, nil
}
