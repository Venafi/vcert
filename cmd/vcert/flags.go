package main

import (
	"github.com/urfave/cli/v2"
)

var (
	flagUrl = &cli.StringFlag{
		Name:  "url",
		Usage: "",
		Aliases: []string["venafi-saas-url", "tpp-url", "u"]
	}
	flagKey = &cli.StringFlag{
		Name:  "apikey",
		Usage: "",
		Aliases: []string{"k"},
	}
)