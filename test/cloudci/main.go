/*
 * Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
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

// Command cloudci manages the cloud providers and keystores the vcert CI
// tests against: it creates them in a tenant, checks the CRUD operations on
// them, and deletes them, along with the certificates provisioned to them.
// See README.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

const (
	targetVCP  = "vcp"
	targetNGTS = "ngts"
)

var logOutput io.Writer = os.Stderr

func logf(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(logOutput, "cloudci: "+format+"\n", args...)
}

func usage() {
	_, _ = fmt.Fprint(os.Stderr, `usage: cloudci setup|check|teardown -target vcp|ngts -state FILE [-aws-config FILE] [-azure-config FILE]

  setup     create and validate the cloud providers, then create their keystores
  check     run the CRUD checks on what setup created
  teardown  delete the provisioned certificates, the keystores and the cloud providers

Connection (environment):
  vcp:  CLOUD_APIKEY, and CLOUD_URL for a platform other than production
  ngts: NGTS_URL, NGTS_TOKEN_URL, NGTS_CLIENT_ID, NGTS_CLIENT_SECRET, NGTS_SCOPE

Secrets missing from the configuration files are read from
AWS_CRUD_SECRET_ACCESS_KEY_<n> and AZURE_CRUD_CLIENT_SECRET_<n>, where <n> is
the provider's position in the file, starting at 0.

`)
	flag.PrintDefaults()
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	command := args[0]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	target := fs.String("target", "", "platform: vcp or ngts")
	statePath := fs.String("state", "", "state file written by setup and read by check and teardown")
	awsConfig := fs.String("aws-config", "", "path of the AWS CRUD configuration (aws_crud.json)")
	azureConfig := fs.String("azure-config", "", "path of the Azure CRUD configuration (azure_crud.json)")
	runID := fs.String("run-id", envOr("BUILD_NUMBER", "local"), "identifier of this run, part of the names it creates")
	validationTimeout := fs.Duration("validation-timeout", 10*time.Minute, "how long setup retries validating a cloud provider")
	staleAfter := fs.Duration("stale-after", 3*time.Hour, "age after which objects of another run are considered left behind")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *target != targetVCP && *target != targetNGTS {
		logf("-target must be %s or %s", targetVCP, targetNGTS)
		return 2
	}
	if *statePath == "" || (*awsConfig == "" && *azureConfig == "") {
		logf("-state and at least one of -aws-config and -azure-config are required")
		return 2
	}

	l := &lifecycle{
		target:             *target,
		runID:              *runID,
		cleaner:            newCloudCleaner(),
		now:                time.Now,
		staleAfter:         *staleAfter,
		validationTimeout:  *validationTimeout,
		validationInterval: 15 * time.Second,
	}
	// setup replaces the state file first, so that a file left by an
	// earlier run in the same workspace cannot be torn down again if setup
	// fails before creating anything
	var st *state
	if command == "setup" {
		st = &state{Target: *target, RunID: *runID}
		if err := st.save(*statePath); err != nil {
			logf("%s", err)
			return 1
		}
	}

	var err error
	if *awsConfig != "" {
		if l.aws, err = loadAWSConfig(*awsConfig, os.Getenv); err != nil {
			logf("%s", err)
			return 1
		}
	}
	if *azureConfig != "" {
		if l.azure, err = loadAzureConfig(*azureConfig, os.Getenv, time.Now()); err != nil {
			logf("%s", err)
			return 1
		}
	}

	// check and teardown need nothing when setup did not run, was skipped or
	// created nothing
	if command != "setup" {
		if st, err = loadState(*statePath); err != nil {
			logf("%s", err)
			return 1
		}
		if st == nil || st.Skipped || len(st.Providers) == 0 {
			logf("nothing to %s: setup did not create anything", command)
			return 0
		}
		if st.Target != *target || st.RunID != *runID {
			logf("state file %s was written by run %q for %s, not by run %q for %s", *statePath, st.RunID, st.Target, *runID, *target)
			return 1
		}
	}

	if l.manager, err = connect(*target); err != nil {
		logf("%s", err)
		return 1
	}

	switch command {
	case "setup":
		save := func() error { return st.save(*statePath) }
		err = l.setup(st, save)
		if errors.Is(err, errSkipped) {
			logf("SKIPPED: %s", st.SkipReason)
			if err := save(); err != nil {
				logf("%s", err)
				return 1
			}
			return 0
		}
	case "check":
		err = l.runChecks(st)
	case "teardown":
		err = l.teardown(st)
	default:
		usage()
		return 2
	}
	if err != nil {
		logf("%s failed: %s", command, err)
		return 1
	}
	logf("%s done", command)
	return 0
}

func envOr(name string, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// connect returns an authenticated connection to the target platform
func connect(target string) (cloudManager, error) {
	var cfg vcert.Config
	switch target {
	case targetVCP:
		if os.Getenv("CLOUD_APIKEY") == "" {
			return nil, errors.New("CLOUD_APIKEY is required for vcp")
		}
		cfg = vcert.Config{
			ConnectorType: endpoint.ConnectorTypeCloud,
			BaseUrl:       os.Getenv("CLOUD_URL"),
			Credentials:   &endpoint.Authentication{APIKey: os.Getenv("CLOUD_APIKEY")},
		}
	case targetNGTS:
		for _, name := range []string{"NGTS_URL", "NGTS_TOKEN_URL", "NGTS_CLIENT_ID", "NGTS_CLIENT_SECRET"} {
			if os.Getenv(name) == "" {
				return nil, fmt.Errorf("%s is required for ngts", name)
			}
		}
		cfg = vcert.Config{
			ConnectorType: endpoint.ConnectorTypeNGTS,
			BaseUrl:       os.Getenv("NGTS_URL"),
			Credentials: &endpoint.Authentication{
				TokenURL:     os.Getenv("NGTS_TOKEN_URL"),
				ClientId:     os.Getenv("NGTS_CLIENT_ID"),
				ClientSecret: os.Getenv("NGTS_CLIENT_SECRET"),
				Scope:        os.Getenv("NGTS_SCOPE"),
			},
		}
	}
	connector, err := vcert.NewClient(&cfg)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to %s: %w", target, err)
	}
	manager, ok := connector.(cloudManager)
	if !ok {
		return nil, fmt.Errorf("the %s connector cannot manage cloud providers and keystores", target)
	}
	return manager, nil
}
