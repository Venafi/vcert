package options

// GlobalOptions represents the flags that can be used by the cli tool at the global level.
//
// They can be passed to any subcommand as well.
type GlobalOptions struct {
	Debug bool
}

// NewGlobalOptions return global options initialized with default values
func NewGlobalOptions() *GlobalOptions {
	return &GlobalOptions{
		Debug: false,
	}
}
