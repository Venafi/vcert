package main

import (
	"github.com/urfave/cli/v2"
	"os"
)

const (
	tppTokenTestFlagValue = "tppTokenTest"
	tppZoneTestFlagValue  = "tppZoneTest"
	tppURlTestFlagValue   = "www.test.venafile.com"
	cloudApiKeyTestValue  = "apiKeyTest"
	cloudZoneTestValue    = "cloudZoneTest"
	validDaysData         = "20#M"
	invalidDaysData       = "0#S"
)

func setEnvironmentVariablesForTpp() {
	os.Setenv(vCertZone, "devops")
	os.Setenv(vCertURL, "www.tpp.venafi.com")
	os.Setenv(vCertToken, "abvcekjej3232ssss")
}

func unsetEnvironmentVariables() {
	os.Unsetenv(vCertZone)
	os.Unsetenv(vCertURL)
	os.Unsetenv(vCertToken)
	os.Unsetenv(vCertApiKey)
	os.Unsetenv(vCertTrustBundle)
}

func getCliContext(command string) *cli.Context {
	context := &cli.Context{
		Command: &cli.Command{
			Name: command,
		},
	}
	return context
}

func setEnvironmentVariablesForCloud() {
	os.Setenv(vCertZone, "devops")
	os.Setenv(vCertApiKey, "abvcekjej3232ssss")
}

func setEnvironmentVariableForTrustBundle() {
	os.Setenv(vCertTrustBundle, "user/tmp/server.pem")
}

func unsetFlags() {
	flags.tppToken = ""
	flags.zone = ""
	flags.url = ""
	flags.validDays = ""
	flags.config = ""
	flags.testMode = false
}

func setEmptyCredentials() {
	flags.config = "fake config"
	flags.apiKey = ""
	flags.password = ""
	flags.tppToken = ""
	flags.testMode = true
}
