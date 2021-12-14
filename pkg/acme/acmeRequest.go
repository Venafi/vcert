package venafi_acme

type AcmeRequest struct {
	DirUrl      string
	Contact     string
	Webroot     string
	Domains     string
	AccountFile string
	CertFile    string
	KeyFile     string
}

type AcmeResponse struct {
}

type acmeAccountFile struct {
	PrivateKey string `json:"privateKey"`
	Url        string `json:"url"`
}
