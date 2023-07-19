package domain

// Config contains all the values necessary to connect to a given Venafi platform: TPP or TLSPC
type Config struct {
	Connection Connection `yaml:"connection,omitempty"`
	ForceRenew bool       `yaml:"-"`
}

// IsValid Ensures the provided connection configuration is valid and logical
func (c Config) IsValid() (bool, error) {
	return c.Connection.IsValid()
}
