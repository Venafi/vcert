package cloudproviders

type CloudProvider struct {
	ID             string
	Name           string
	Type           string
	Status         string
	StatusDetails  string
	KeystoresCount int
}
