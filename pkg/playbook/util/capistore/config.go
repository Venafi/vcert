//go:*build windows

package capistore

type InstallationConfig struct {
	PFX             []byte
	FriendlyName    string
	IsNonExportable bool
	Password        string
	StoreLocation   string
	StoreName       string
}
