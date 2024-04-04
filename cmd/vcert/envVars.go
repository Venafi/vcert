package main

import "fmt"

const (
	vCertPlatform     = "VCERT_PLATFORM"
	vCertURL          = "VCERT_URL"
	vCertZone         = "VCERT_ZONE"
	vCertToken        = "VCERT_TOKEN"  // #nosec G101
	vCertApiKey       = "VCERT_APIKEY" // #nosec G101
	vCertIdPJWT       = "VCERT_IDP_JWT"
	vCertTokenURL     = "VCERT_TOKEN_URL" // #nosec G101
	vCertTrustBundle  = "VCERT_TRUST_BUNDLE"
	vcertUser         = "VCERT_USER"
	vcertPassword     = "VCERT_PASSWORD"
	vcertClientID     = "VCERT_CLIENT_ID"
	vcertClientSecret = "VCERT_CLIENT_SECRET" // #nosec G101
	vcertDeviceURL    = "VCERT_DEVICE_URL"
)

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
			EnvVarName:  vCertTokenURL,
			Destination: &flags.tokenURL,
			FlagName:    "--token-url",
		},
		{
			EnvVarName:  vCertIdPJWT,
			Destination: &flags.idPJWT,
			FlagName:    "--idp-jwt",
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
			FlagName:    "--client-secret",
		},
		{
			EnvVarName:  vcertClientID,
			Destination: &flags.clientId,
			FlagName:    "--client-id",
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

	warnMsg := "Warning: command line parameter %s has overridden environment variable %s"

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
