package cloudproviders

import "github.com/google/uuid"

type CloudProvider struct {
	ID             uuid.UUID
	Name           string
	Type           string
	Status         string
	StatusDetails  string
	KeystoresCount int
}
