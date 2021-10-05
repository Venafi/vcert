package certificate

type SshCaTemplateRequest struct {
	Template string
	Guid     string
}

type SshTppCaTemplateRequest struct {
	DN   string `json:"DN,omitempty"`
	Guid string `json:"Guid,omitempty"`
}

type SshTppCaTemplateResponse struct {
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
