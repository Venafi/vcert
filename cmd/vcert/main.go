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

func init() {
	log.SetPrefix(UtilityShortName + ": ")
}

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
			commandProvision,
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
   Command       Platform             Description

   gencsr                             To generate a certificate signing request (CSR)
   enroll        tpp | vcp | firefly  To enroll a certificate
   pickup        tpp | vcp            To retrieve a certificate
   renew         tpp | vcp            To renew a certificate
   retire        tpp | vcp            To retire a certificate
   revoke        tpp                  To revoke a certificate
   run           tpp | vcp | firefly  To retrieve and install certificates using a vcert playbook file
   provision           vcp            To provision a certificate to cloud keystore

   getpolicy     tpp | vcp            To retrieve the certificate policy of a zone
   setpolicy     tpp | vcp            To apply a certificate policy specification to a zone

   getcred       tpp | vcp | oidc     To obtain a new authentication token from any Venafi platform or to register for a new Venafi Control Plane user API key
   checkcred     tpp                  To check the validity of a Trust Protection Platform token and grant
   voidcred      tpp                  To invalidate a Trust Protection Platform authentication token

   sshenroll     tpp                  To enroll an SSH certificate
   sshpickup     tpp                  To retrieve an SSH certificate
   sshgetconfig  tpp                  To get the SSH CA public key and default principals

OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}
COPYRIGHT:
   {{.Copyright}}
   {{end}}{{if .Version}}
SUPPORT:
   opensource@venafi.com
{{end}}
`, vcert.GetFormattedVersionString(), vcert.GetFormatedBuildTimeStamp())

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
