package venafi_acme

type AcmeRequest struct {
	DirUrl      string
	Contact     string
	Webroot     string
	Domains     string
	AccountFile string
	CertFile    string
	KeyFile     string
	ReuseKey    bool
}

type AcmeRenewSvcRequest struct {
	AcmeRequest
	RenewWindow int
	ApiKey      string
	Zone        string
}
type AcmeResponse struct {
}

type acmeAccountFile struct {
	PrivateKey string `json:"privateKey"`
	Url        string `json:"url"`
}
