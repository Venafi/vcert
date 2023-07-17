package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/Venafi/vcert/v4/pkg/playbook/options"
	"github.com/Venafi/vcert/v4/pkg/playbook/util"
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&globalOptions.Debug, "debug", "d", false, "Enables debug log messages")
}

var (
	globalOptions = options.NewGlobalOptions()
	rootCmd       = &cobra.Command{
		Use:   "vcp",
		Short: "Retrieve and install certificates using a vcert playbook file",
		Long: `Enables users to request and retrieve one or more certificates, 
	install them as either CAPI, JKS, PEM, or PKCS#12, run after-install operations 
	(script, command-line instruction, etc.), and monitor certificate(s) for renewal 
	on subsequent runs.`,
		Version: util.GetFormattedVersionString(),
	}
)

// Execute runs the cli tool root command
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
