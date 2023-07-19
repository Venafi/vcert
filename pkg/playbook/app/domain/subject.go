package domain

// Subject represents the X.509 distinguished names of the certificate.
// This only includes the common elements of a DN
type Subject struct {
	CommonName   string   `yaml:"commonName,omitempty"`
	Country      string   `yaml:"country,omitempty"`
	Locality     string   `yaml:"locality,omitempty"`
	Organization string   `yaml:"organization,omitempty"`
	OrgUnits     []string `yaml:"orgUnits,omitempty"`
	Province     string   `yaml:"province,omitempty"`
}
