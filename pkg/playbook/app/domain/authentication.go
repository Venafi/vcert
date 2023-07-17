package domain

// Authentication holds the credentials to connect to Venafi platforms: TPP and TLSPC
type Authentication struct {
	AccessToken  string `yaml:"accessToken,omitempty"`
	Apikey       string `yaml:"apikey,omitempty"`
	ClientID     string `yaml:"clientId,omitempty"`
	RefreshToken string `yaml:"refreshToken,omitempty"`
	Scope        string `yaml:"scope,omitempty"`
	PKCS12       string `yaml:"pkcs12,omitempty"`
}

// IsEmpty returns true if not credentials are set
func (a Authentication) IsEmpty() bool {
	// TODO: This is very hacky.. need specifics based on connection type
	if a.Apikey == "" && a.AccessToken == "" && a.RefreshToken == "" && a.PKCS12 == "" {
		return true
	}
	return false
}
