package main

import (
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"
)

var (
	commandProvision = &cli.Command{
		Before:      runBeforeCommand,
		Action:      doCommandProvision,
		Name:        commandProvisionName,
		Usage:       "To provision a certificate from Venafi Platform to a Cloud Keystore",
		Subcommands: []*cli.Command{subCommandCloudKeystore},
	}
)

func doCommandProvision(c *cli.Context) error {
	return fmt.Errorf("the following subcommand(s) are required: \n%s", createBulletList(provisionCommands))
}

func createBulletList(items []string) string {
	var builder strings.Builder
	for _, item := range items {
		builder.WriteString("• ")
		builder.WriteString(item)
		builder.WriteString("\n")
	}
	return builder.String()
}
