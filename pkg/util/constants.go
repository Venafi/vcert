package util

const (
	PathSeparator           = "\\"
	ApplicationServerTypeID = "784938d1-ef0d-11eb-9461-7bb533ba575b"
)

type IssuerHint string

const (
	IssuerHintMicrosoft  IssuerHint = "MICROSOFT"
	IssuerHintDigicert   IssuerHint = "DIGICERT"
	IssuerHintEntrust    IssuerHint = "ENTRUST"
	IssuerHintAllIssuers IssuerHint = "ALL_ISSUERS"
	IssuerHintGeneric    IssuerHint = ""
)
