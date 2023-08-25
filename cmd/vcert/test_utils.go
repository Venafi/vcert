package main

import (
	"os"

	"github.com/urfave/cli/v2"
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
	os.Unsetenv(vCertPlatform)
	os.Unsetenv(vcertUser)
	os.Unsetenv(vCertPlatform)
	os.Unsetenv(vcertClientID)
	os.Unsetenv(vcertClientSecret)
	os.Unsetenv(vcertDeviceURL)
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
	flags.token = ""
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
	flags.token = ""
	flags.testMode = true
}
