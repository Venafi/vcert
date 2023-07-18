package util

import "go.uber.org/zap"

// ConfigureLogger sets the default values for the cli logger
func ConfigureLogger(debug bool) error {
	zc := zap.NewDevelopmentConfig()
	if !debug {
		zc.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		zc.DisableStacktrace = true
	}
	l, err := zc.Build()
	if err != nil {
		return err
	}
	zap.ReplaceGlobals(l)

	return nil
}
