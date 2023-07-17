package options

const (
	// DefaultFilepath represents the default location to look for a valid Playbook file
	DefaultFilepath = "./playbook.yaml"
	// TlspcURL represents the default TLSPC service url
	TlspcURL = "api.venafi.cloud"
)

// RunOptions represents the flags that can be passed to the run subcommand
type RunOptions struct {
	Filepath      string
	Force         bool
	ScheduleTimer string
}

// NewRunOptions return global options initialized with default values
func NewRunOptions() *RunOptions {
	return &RunOptions{
		Filepath: DefaultFilepath,
		Force:    false,
	}
}
