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

func getCliContext() *cli.Context {
	context := &cli.Context{
		Command: &cli.Command{
			Name: "getCred",
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
}
