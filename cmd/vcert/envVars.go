package main

import "fmt"

type envVar struct {
	EnvVarName  string
	Destination *string
	FlagName    string
}

var (
	envVarList = []envVar{
		{
			EnvVarName:  vCertPlatform,
			Destination: &flags.platformString,
			FlagName:    "--platform",
		},
		{
			EnvVarName:  vCertURL,
			Destination: &flags.url,
			FlagName:    "-u",
		},
		{
			EnvVarName:  vCertZone,
			Destination: &flags.zone,
			FlagName:    "-z",
		},
		{
			EnvVarName:  vCertToken,
			Destination: &flags.token,
			FlagName:    "-t",
		},
		{
			EnvVarName:  vCertApiKey,
			Destination: &flags.apiKey,
			FlagName:    "-k",
		},
		{
			EnvVarName:  vCertTrustBundle,
			Destination: &flags.trustBundle,
			FlagName:    "--trust-bundle",
		},

		{
			EnvVarName:  vcertUser,
			Destination: &flags.userName,
			FlagName:    "--username",
		},
		{
			EnvVarName:  vcertPassword,
			Destination: &flags.password,
			FlagName:    "--password",
		},
		{
			EnvVarName:  vcertClientSecret,
			Destination: &flags.clientSecret,
			FlagName:    "--client-id",
		},
		{
			EnvVarName:  vcertClientID,
			Destination: &flags.clientId,
			FlagName:    "--client-secret",
		},
		{
			EnvVarName:  vcertTokenURL,
			Destination: &flags.tokenURL,
			FlagName:    "--token-url",
		},
		{
			EnvVarName:  vcertDeviceURL,
			Destination: &flags.deviceURL,
			FlagName:    "--device-url",
		},
	}
)

func assignEnvVarsToFlags() {
	colorYellow := "\033[33m"
	colorReset := "\033[0m"

	warnMsg := "Warning Command line parameter %s has overridden environment variable %s"

	for _, item := range envVarList {
		value := getPropertyFromEnvironment(item.EnvVarName)
		if value == "" {
			continue
		}
		if *item.Destination != "" {
			logger.Println(colorYellow, fmt.Sprintf(warnMsg, item.FlagName, item.EnvVarName), colorReset)
		} else {
			*item.Destination = value
		}
	}
}