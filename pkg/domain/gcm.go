package domain

import "strings"

// GCMCertificateScope Indicates the Scope for a certificate provisioned to GCP Certificate Manager
type GCMCertificateScope string

var (
	// GCMCertificateScopeDefault Certificates with default scope are served from core Google data centers.
	// If unsure, choose this option.
	GCMCertificateScopeDefault GCMCertificateScope = addCertificateScope("DEFAULT")

	// GCMCertificateScopeEdgeCache Certificates with scope EDGE_CACHE are special-purposed certificates,
	// served from Edge Points of Presence.
	// See https://cloud.google.com/vpc/docs/edge-locations.
	GCMCertificateScopeEdgeCache GCMCertificateScope = addCertificateScope("EDGE_CACHE")

	// GCMCertificateScopeAllRegions Certificates with ALL_REGIONS scope are served from all Google Cloud regions
	// See https://cloud.google.com/compute/docs/regions-zones.
	GCMCertificateScopeAllRegions GCMCertificateScope = addCertificateScope("ALL_REGIONS")

	// GCMCertificateScopeUnknow value to set that the Certificate Scope is not matching to any of the valid scopes.
	GCMCertificateScopeUnknow GCMCertificateScope = addCertificateScope("UNKNOWN")
)

var GCMCertificateScopes = map[GCMCertificateScope]bool{}

func addCertificateScope(scope string) GCMCertificateScope {
	scope = strings.ToUpper(scope)

	certificateScope := GCMCertificateScope(scope)

	if !GCMCertificateScopes[certificateScope] {
		GCMCertificateScopes[certificateScope] = true
	}

	return certificateScope
}

func GetScopeFromString(scope string) GCMCertificateScope {
	scope = strings.ToUpper(scope)

	certificateScope := GCMCertificateScope(scope)

	if !GCMCertificateScopes[certificateScope] {
		return GCMCertificateScopeUnknow
	}

	return certificateScope
}
