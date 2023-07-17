//go:build !windows

package util

import (
	"bytes"
	"fmt"
	"os/exec"

	"go.uber.org/zap"
)

// ExecuteScript takes the afterAction input and passes it to a Cmd struct to be executed.
//
// No validation is done over the afterAction string, so caution is advised.
func ExecuteScript(afterAction string) (string, error) {
	zap.L().Debug(fmt.Sprintf("running After-install actions: %s", afterAction))

	cmd := exec.Command("sh", "-c", afterAction)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		zap.L().Error(fmt.Sprintf("could not run after-install action: %s", err.Error()))
		return "", err
	}
	zap.L().Debug(fmt.Sprintf("after-install output: %s", out.String()))
	return out.String(), nil
}
