package main

import (
	"fmt"
	"os"

	"github.com/Venafi/vcert/v4/pkg/playbook/util"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"

	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/parser"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/service"
	"github.com/Venafi/vcert/v4/pkg/playbook/options"
)

const commandRunPlaybookName = "run"

var commandRunPlaybook = &cli.Command{
	Name: commandRunPlaybookName,
	Usage: `Enables users to request and retrieve one or more certificates, 
	install them as either CAPI, JKS, PEM, or PKCS#12, run after-install operations 
	(script, command-line instruction, etc.), and monitor certificate(s) for renewal 
	on subsequent runs.`,
	//"Retrieve and install certificates using a vcert playbook file",
	UsageText: `vcert run
	 vcert run -f /path/to/my/file.yml
	 vcert run -f ./myFile.yaml --force-renew
	 vcert run -f ./myFile.yaml --debug`,
	Action: doRunPlaybook,
	Flags:  playbookFlags,
}

var (
	playbookOptions options.RunOptions
	globalOptions   options.GlobalOptions

	PBFlagFilepath = &cli.StringFlag{
		Name:        "file",
		Aliases:     []string{"f"},
		Usage:       "the path to the playbook file to be run",
		Required:    true,
		Value:       options.DefaultFilepath,
		Destination: &playbookOptions.Filepath,
	}

	PBFlagForce = &cli.BoolFlag{
		Name:        "force-renew",
		Aliases:     nil,
		Usage:       "forces certificate renewal regardless of expiration date or renew window",
		Required:    false,
		Value:       false,
		Destination: &playbookOptions.Force,
	}

	PBFlagDebug = &cli.BoolFlag{
		Name:        "debug",
		Aliases:     []string{"d"},
		Usage:       "Enables debug log messages",
		Required:    false,
		Value:       false,
		Destination: &globalOptions.Debug,
	}

	playbookFlags = flagsApppend(
		PBFlagFilepath,
		PBFlagForce,
		PBFlagDebug,
	)
)

func doRunPlaybook(c *cli.Context) error {
	err := util.ConfigureLogger(globalOptions.Debug)
	if err != nil {
		return err
	}
	zap.L().Info(fmt.Sprintf("running with playbook file at %s", playbookOptions.Filepath))
	zap.L().Debug("debug is enabled")

	playbook, err := parser.ReadPlaybook(playbookOptions.Filepath)
	if err != nil {
		zap.L().Error(fmt.Errorf("%w", err).Error())
		os.Exit(1)
	}

	_, err = playbook.IsValid()
	if err != nil {
		zap.L().Error(fmt.Errorf("playbook '%v' is invalid: \n%w", playbookOptions.Filepath, err).Error())
		os.Exit(1)
	}

	//Set the forceRenew variable
	playbook.Config.ForceRenew = playbookOptions.Force

	if len(playbook.CertificateTasks) == 0 {
		zap.L().Info("no tasks in the playbook. Nothing to do")
		return nil
	}

	// emulate the setTLSConfig from vcert
	err = setTLSConfig()
	if err != nil {
		zap.L().Error(fmt.Sprintf("%v", err))
		os.Exit(1)
	}

	if playbook.Config.Connection.Type == domain.CTypeTPP {
		err = service.ValidateTPPCredentials(&playbook)
		if err != nil {
			zap.L().Error(fmt.Sprintf("%v", err))
			os.Exit(1)
		}
	}

	for _, certTask := range playbook.CertificateTasks {
		zap.L().Info(fmt.Sprintf("running task: %s", certTask.Name))
		errors := service.Execute(playbook.Config, certTask)
		if len(errors) > 0 {
			for _, err2 := range errors {
				zap.L().Error(fmt.Sprintf("error running task '%s': %v", certTask.Name, err2))
			}
			os.Exit(1)
		}
	}

	zap.L().Info("playbook run finished")
	return nil
}
