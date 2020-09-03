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
	"github.com/Venafi/vcert/v4"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"sort"
	"time"
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

	app := &cli.App{
		Usage: UtilityName,
		UsageText: `vcert action [action options]
   for command help run: vcert action -h`,
		Version:  vcert.GetFormattedVersionString(), //todo: replace with plain version
		Compiled: time.Now(),                        //todo: replace with parsing vcert.versionBuildTimeStamp
		Commands: []*cli.Command{
			commandGetcred,
			commandGenCSR,
			commandEnroll,
			commandPickup,
			commandRenew,
			commandRevoke,
		},
		EnableBashCompletion: true, //todo: write BashComplete function for options
		//HideHelp:             true,
		Copyright: `2020 Venafi, Inc.
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
   {{range .Authors}}{{ . }}{{end}}
   {{end}}{{if .Commands}}
ACTIONS:
   enroll   To enroll a certificate,
   gencsr   To generate a certificate signing request (CSR)
   getcred  To obtain a new token for authentication
   pickup   To retrieve a certificate
   renew    To renew a certificate
   revoke   To revoke a certificate

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
	err := app.Run(os.Args)
	if err != nil {
		//TODO: we need to make logger a global package
		logger := log.New(os.Stderr, UtilityShortName+": ", log.LstdFlags)
		logger.Panicf("%s", err)
	}
}
