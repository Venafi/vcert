/*
 * Copyright 2018-2023 Venafi, Inc.
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
	"log"
	"os"
	"sort"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/util"
)

var (
	logger = log.New(os.Stderr, UtilityShortName+": ", log.LstdFlags)
	logf   = logger.Printf
	exit   = os.Exit
)

// UtilityName is the full name of the command-line utility
const UtilityName string = "Venafi Certificate Utility"

// UtilityShortName is the short name of the command-line utility
const UtilityShortName string = "vCert"

// OriginName is the full name for adding to meta information to certificate request
const OriginName = "Venafi VCert CLI"

func main() {
	defer func() {
		if r := recover(); r != nil {
			// logger.Fatalf() does immediately os.Exit(1)
			// so we use logger.Panic() and do recover() here to hide stacktrace
			// exit() is a function to decide what to do

			exit(1)  // it's os.Exit() by default, but can be overridden
			panic(r) // so that panic() bubbling continues (it's needed when we call main() from cli_test.go)

		}
	}()

	//Configure zap logger
	err := util.ConfigureLogger(false)
	if err != nil {
		l := log.New(os.Stderr, UtilityShortName+": ", log.LstdFlags)
		l.Panicf("%s", err)
	}

	app := &cli.App{
		Usage: UtilityName,
		UsageText: `vcert action [action options]
   for command help run: vcert action -h`,
		Version:  vcert.GetFormattedVersionString(), //todo: replace with plain version
		Compiled: time.Now(),                        //todo: replace with parsing vcert.versionBuildTimeStamp
		Commands: []*cli.Command{
			commandGetCred,
			commandCheckCred,
			commandVoidCred,
			commandGenCSR,
			commandEnroll,
			commandPickup,
			commandRenew,
			commandRevoke,
			commandRetire,
			commandCreatePolicy,
			commandGetPolicy,
			commandSshPickup,
			commandSshEnroll,
			commandSshGetConfig,
			commandRunPlaybook,
		},
		EnableBashCompletion: true, //todo: write BashComplete function for options
		Authors:              authors,
		Copyright: `2018-2023 Venafi, Inc.
	 Licensed under the Apache License, Version 2.0`,
	}

	sort.Sort(cli.CommandsByName(app.Commands))

	cli.AppHelpTemplate = fmt.Sprintf(`Venafi Certificate Utility
   Version: %s
   Build Timestamp: %s

USAGE:
   {{.HelpName}} {{if .VisibleFlags}}[global options]{{end}}{{if .Commands}} command [command options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}
   {{if len .Authors}}
AUTHOR:
   {{range .Authors}}{{ . }}
   {{end}}{{end}}{{if .Commands}}
ACTIONS:
   Command       Platform         Description

   gencsr                         To generate a certificate signing request (CSR)
   enroll        TPP | VaaS | FF  To enroll a certificate
   pickup        TPP | VaaS       To retrieve a certificate
   renew         TPP | VaaS       To renew a certificate
   retire        TPP | VaaS       To retire a certificate
   revoke        TPP              To revoke a certificate
   run           TPP | VaaS | FF  To retrieve and install certificates using a vcert playbook file

   getpolicy     TPP | VaaS       To retrieve the certificate policy of a zone
   setpolicy     TPP | VaaS       To apply a certificate policy specification to a zone

   getcred       TPP | VaaS | FF  To obtain a new authentication token from any Venafi platform or to register for a new VaaS user API key
   checkcred     TPP              To check the validity of a token and grant. Only works for TPP platform
   voidcred      TPP              To invalidate an authentication grant. Only works for TPP platform

   sshenroll     TPP              To enroll a SSH certificate
   sshpickup     TPP              To retrieve a SSH certificate
   sshgetconfig  TPP              To get the SSH CA public key and default principals

OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}
COPYRIGHT:
   {{.Copyright}}
   {{end}}{{if .Version}}
SUPPORT:
   opensource@venafi.com
{{end}}
`, vcert.GetFormattedVersionString(), vcert.GetFormattedBuildTimeStamp())

	cli.CommandHelpTemplate = `NAME:
   {{.HelpName}} - {{.Usage}}

USAGE:
   {{if .UsageText}}{{.UsageText}}{{else}}{{.HelpName}}{{if .VisibleFlags}} [command options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}{{end}}{{if .Category}}

CATEGORY:
   {{.Category}}{{end}}{{if .Description}}

DESCRIPTION:
   {{.Description}}{{end}}{{if .VisibleFlags}}

OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}{{end}}
`
	err = app.Run(os.Args)
	if err != nil {
		//TODO: we need to make logger a global package
		l := log.New(os.Stderr, UtilityShortName+": ", log.LstdFlags)
		l.Panicf("%s", err)
	}
}

var authors = []*cli.Author{
	{
		Name:  "Ryan Treat",
		Email: "ryan.treat@venafi.com",
	},
	{
		Name:  "Russel Vela",
		Email: "russel.vela@venafi.com",
	},
	{
		Name:  "Luis Presuel",
		Email: "luis.presuel@venafi.com",
	},
	{
		Name:  "Marcos Albornoz",
		Email: "marcos.albornoz@venafi.com",
	},
}
