package certificate

type CaTemplateRequest struct {
	Dn   string
	Guid string
}

type TppCaTemplateRequest struct {
	Dn   string `json:"DN,omitempty"`
	Guid string `json:"Guid,omitempty"`
}

type CaTemplateResponse struct {
	AccessControl AccessControl
	Response      TppSshCertResponseInfo `json:"Response,omitempty"`
}

type AccessControl struct {
	DefaultPrincipals []string
}

type SshConfig struct {
	CaPublicKey string
	Principals  []string
}
