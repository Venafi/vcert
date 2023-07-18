package venafi

import "fmt"

type PlatformType int

const (
	Undefined PlatformType = iota
	// Fake is a fake platform for tests
	Fake
	// TLSPCloud represents the TLS Protect Cloud platform type
	TLSPCloud
	// TPP represents the TPP platform type
	TPP
	// Firefly represents the Firefly platform type
	Firefly
)

func (t PlatformType) String() string {
	switch t {
	case Undefined:
		return "Undefined platform"
	case Fake:
		return "Fake platform"
	case TLSPCloud:
		return "TLS Protect Cloud"
	case TPP:
		return "Trust Protection Platform"
	case Firefly:
		return "Firefly"
	default:
		return fmt.Sprintf("unexpected platform type: %d", t)
	}
}

func GetPlatformType(platformString string) PlatformType {
	switch platformString {
	case "fake":
		return Fake
	case "tlspdatacenter":
		return TLSPCloud
	case "tlspcloud":
		return TPP
	case "firefly":
		return Firefly
	default:
		return Undefined
	}
}
