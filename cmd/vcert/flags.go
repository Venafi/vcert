package main

import (
	"github.com/urfave/cli/v2"
)

var (
	flagUrl = &cli.StringFlag{
		Name:        "u",
		Usage:       "",
		Destination: &flags.url,
	}
	flagUrlDeprecated = &cli.StringFlag{
		Name:        "venafi-saas-url",
		Usage:       "",
		Aliases:     []string{"tpp-url"},
		Destination: &flags.url,
		Hidden:      true,
	}
	flagKey = &cli.StringFlag{
		Name:    "apikey",
		Usage:   "",
		Aliases: []string{"k"},
	}
	flagTPPUser = &cli.StringFlag{
		Name:        "tpp-user",
		Usage:       "",
		Destination: &flags.tppUser,
	}
	flagTPPPassword = &cli.StringFlag{
		Name:  "tpp-password",
		Usage: "",
	}
	flagTPPToken = &cli.StringFlag{
		Name:  "t",
		Usage: "",
	}
	flagTrustBundle = &cli.StringFlag{
		Name:  "trust-bundle",
		Usage: "",
	}
	flagZone = &cli.StringFlag{
		Name:  "z",
		Usage: "",
	}
	flagCADN = &cli.StringFlag{
		Name:  "ca-dn",
		Usage: "",
	}
	//todo: problem
	flagKeyCurve = &cli.StringFlag{
		Name:  "key-curve",
		Usage: "",
	}
	//todo: problem
	flagKeyType = &cli.StringFlag{
		Name:  "key-type",
		Usage: "",
	}
	flagKeySize = &cli.IntFlag{
		Name:  "key-size",
		Usage: "",
		Value: 2048,
	}
	flagFriendlyName = &cli.StringFlag{
		Name:  "nickname",
		Usage: "",
	}
	flagCommonName = &cli.StringFlag{
		Name:  "cn",
		Usage: "",
	}
	flagOrg = &cli.StringFlag{
		Name:  "o",
		Usage: "",
	}
	flagState = &cli.StringFlag{
		Name:  "st",
		Usage: "",
	}
	flagCountry = &cli.StringFlag{
		Name:  "c",
		Usage: "",
	}
	flagLocality = &cli.StringFlag{
		Name:  "l",
		Usage: "",
	}
	flagOrgUnits = &cli.StringSliceFlag{
		Name:  "ou",
		Usage: "",
	}
	flagDNSSans = &cli.StringSliceFlag{
		Name:  "san-dns",
		Usage: "",
	}
	//todo: problem
	flagIPSans = &cli.StringSliceFlag{
		Name:  "san-ip",
		Usage: "",
	}
	//todo: problem
	flagEmailSans = &cli.StringSliceFlag{
		Name:  "san-email",
		Usage: "",
	}
	flagFormat = &cli.StringFlag{
		Name:  "format",
		Usage: "",
		Value: "pem",
	}
	flagFile = &cli.StringFlag{
		Name:  "file",
		Usage: "",
	}
	flagKeyFile = &cli.StringFlag{
		Name:  "key-file",
		Usage: "",
	}
	flagCertFile = &cli.StringFlag{
		Name:  "cert-file",
		Usage: "",
	}
	flagChainFile = &cli.StringFlag{
		Name:  "chain-file",
		Usage: "",
	}
	flagChainOption = &cli.StringFlag{
		Name:  "chain",
		Usage: "",
		Value: "root-last",
	}
	flagVerbose = &cli.BoolFlag{
		Name: "verbose",
	}
	flagNoPrompt = &cli.BoolFlag{
		Name: "np-prompt",
	}
	flagNoPickup = &cli.BoolFlag{
		Name: "no-pickup",
	}
	flagTestMode = &cli.BoolFlag{
		Name: "test-mode",
	}
	flagTestModeDelay = &cli.IntFlag{
		Name:  "test-mode-delay",
		Usage: "",
		Value: 15,
	}
	flagCSR = &cli.StringFlag{
		Name:  "csr",
		Usage: "",
	}
	flagKeyPassword = &cli.StringFlag{
		Name:  "key-password",
		Usage: "",
	}
	flagPickupIDFile = &cli.StringFlag{
		Name:  "pickup-id-file",
		Usage: "",
	}
	flagTimeout = &cli.IntFlag{
		Name:  "timeout",
		Value: 180,
		Usage: "",
	}
	flagInsecure = &cli.BoolFlag{
		Name:  "insecure",
		Usage: "",
	}
	flagConfig = &cli.StringFlag{
		Name:  "config",
		Usage: "",
	}
	flagProfile = &cli.StringFlag{
		Name:  "profile",
		Usage: "",
	}
	flagClientP12 = &cli.StringFlag{
		Name:  "client-pkcs12",
		Usage: "",
	}
	flagClientP12PW = &cli.StringFlag{
		Name:  "client-pkcs12p-pw",
		Usage: "",
	}

	commonFlags  = []cli.Flag{flagZone, flagInsecure}                                                                 //todo: add over, rename
	enrollFlags1 = []cli.Flag{flagUrl, flagKey, flagTPPUser, flagTPPToken, flagZone, flagInsecure, flagUrlDeprecated} //todo: add over, rename

)
