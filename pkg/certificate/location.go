package certificate

// Location represents a Device that needs enrollment or provisioning
type Location struct {
	Instance   string `yaml:"instance,omitempty"`
	Workload   string `yaml:"workload,omitempty"`
	TLSAddress string `yaml:"tlsAddress,omitempty"`
	Replace    bool   `yaml:"replace,omitempty"`
}
