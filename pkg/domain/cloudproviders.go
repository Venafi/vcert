package domain

type CloudProvider struct {
	ID             string
	Name           string
	Type           string
	Status         string
	StatusDetails  string
	KeystoresCount int
}

type CloudKeystore struct {
	ID                     string
	Name                   string
	Type                   string
	MachineIdentitiesCount int
}

type ProvisioningResponse struct {
	WorkflowId   string
	WorkflowName string
}
