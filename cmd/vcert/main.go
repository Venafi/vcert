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
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"time"
)

var (
	logger = log.New(os.Stderr, UtilityShortName+": ", log.LstdFlags)
	logf   = logger.Printf
	exit   = os.Exit
)

func init() {
	setupGenCsrCommandFlags()
	setupEnrollCommandFlags()
	setupRetrieveCommandFlags()
	setupRevokeCommandFlags()
	setupRenewCommandFlags()
	setupGetcredCommandFlags()

}

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
		Usage:     UtilityName,
		UsageText: "",
		Version:   GetFormattedVersionString(), //todo: replace with plain version
		Compiled:  time.Now(),                  //todo: replace with parsing vcert.versionBuildTimeStamp
		Commands: []*cli.Command{
			commandGetcred1,
			commandGenCSR1,
			commandEnroll1,
			commandPickup1,
			commandRenew1,
			commandRevoke1,
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	return
}
