//go:*build windows

package capistore

import (
	_ "embed"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const validInputRegex string = `^[A-Za-z0-9\s-_\.]+$` // regex for validating keystore and binding fields to prevent commandline injection

func psBool(b bool) string {
	if b {
		return "1" // Represents True
	}
	return "0" // Represents False
}

func containsInjectableData(value string) error {
	if len(value) == 0 {
		return nil
	}

	re := regexp.MustCompile(validInputRegex)
	if !re.MatchString(value) {
		return errors.New("the input contained invalid characters")
	}
	return nil
}

func copyScript(script, scriptPath string) error {
	input := []byte(script)

	err := os.WriteFile(scriptPath, input, 0644)
	if err != nil {
		zap.L().Error("Error creating script file")
		return err
	}

	return nil
}

func quoteIfNeeded(s string) string {
	if strings.ContainsAny(s, "\t ") && !strings.HasSuffix(s, "'") && !strings.HasPrefix(s, "'") {
		return fmt.Sprintf("'%s'", s)
	}
	return s
}
