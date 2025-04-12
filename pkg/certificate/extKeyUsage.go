/*
 * Copyright 2022 Venafi, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/Venafi/vcert/v5/pkg/verror"
	"gopkg.in/yaml.v3"
)

/*
	  type ExtKeyUsage struct {
		 id   x509.ExtKeyUsage
		 oid  asn1.ObjectIdentifier
		 name string
	 }
*/
// ExtKeyUsage represents an extended set of actions that are valid for a given key.
// Each of the ExtKeyUsage* constants define a unique action.
type ExtKeyUsage x509.ExtKeyUsage

const (
	strUnknownExtKeyUsage                        = "UnknownExtKeyUsage"
	strExtKeyUsageAny                            = "Any"
	strExtKeyUsageServerAuth                     = "ServerAuth"
	strExtKeyUsageClientAuth                     = "ClientAuth"
	strExtKeyUsageCodeSigning                    = "CodeSigning"
	strExtKeyUsageEmailProtection                = "EmailProtection"
	strExtKeyUsageIPSECEndSystem                 = "IPSECEndSystem"
	strExtKeyUsageIPSECTunnel                    = "IPSECTunnel"
	strExtKeyUsageIPSECUser                      = "IPSECUser"
	strExtKeyUsageTimeStamping                   = "TimeStamping"
	strExtKeyUsageOCSPSigning                    = "OCSPSigning"
	strExtKeyUsageMicrosoftServerGatedCrypto     = "MicrosoftServerGatedCrypto"
	strExtKeyUsageNetscapeServerGatedCrypto      = "NetscapeServerGatedCrypto"
	strExtKeyUsageMicrosoftCommercialCodeSigning = "MicrosoftCommercialCodeSigning"
	strExtKeyUsageMicrosoftKernelCodeSigning     = "MicrosoftKernelCodeSigning"

	// Unknown ExtKeyUsage. WARNING: crypto/x509.ExtKeyUsage does not declare an undefined
	// ExtKeyUsage constant!
	UnknownExtKeyUsage ExtKeyUsage = -1
	// ExtKeyUsageAny represents an EKU of Any (oid: 2.5.29.37.0)
	ExtKeyUsageAny = ExtKeyUsage(x509.ExtKeyUsageAny)
	// ExtKeyUsageServerAuth represents an EKU of ServerAuth (oid: 1.3.6.1.5.5.7.3.1)
	ExtKeyUsageServerAuth = ExtKeyUsage(x509.ExtKeyUsageServerAuth)
	// ExtKeyUsageClientAuth represents an EKU of ClientAuth (oid: 1.3.6.1.5.5.7.3.2)
	ExtKeyUsageClientAuth = ExtKeyUsage(x509.ExtKeyUsageClientAuth)
	// ExtKeyUsageCodeSigning represents an EKU of CodeSigning (oid: 1.3.6.1.5.5.7.3.3)
	ExtKeyUsageCodeSigning = ExtKeyUsage(x509.ExtKeyUsageCodeSigning)
	// ExtKeyUsageEmailProtection represents an EKU of EmailProtection (oid: 1.3.6.1.5.5.7.3.4)
	ExtKeyUsageEmailProtection = ExtKeyUsage(x509.ExtKeyUsageEmailProtection)
	// ExtKeyUsageIPSECEndSystem represents an EKU of IPSECEndSystem (oid: 1.3.6.1.5.5.7.3.5)
	ExtKeyUsageIPSECEndSystem = ExtKeyUsage(x509.ExtKeyUsageIPSECEndSystem)
	// ExtKeyUsageIPSECTunnel represents an EKU of IPSECTunnel (oid: 1.3.6.1.5.5.7.3.6)
	ExtKeyUsageIPSECTunnel = ExtKeyUsage(x509.ExtKeyUsageIPSECTunnel)
	// ExtKeyUsageIPSECUser represents an EKU of IPSECUser (oid: 1.3.6.1.5.5.7.3.7)
	ExtKeyUsageIPSECUser = ExtKeyUsage(x509.ExtKeyUsageIPSECUser)
	// ExtKeyUsageTimeStamping represents an EKU of TimeStamping (oid: 1.3.6.1.5.5.7.3.8)
	ExtKeyUsageTimeStamping = ExtKeyUsage(x509.ExtKeyUsageTimeStamping)
	// ExtKeyUsageOCSPSigning represents an EKU of OCSPSigning (oid: 1.3.6.1.5.5.7.3.9)
	ExtKeyUsageOCSPSigning = ExtKeyUsage(x509.ExtKeyUsageOCSPSigning)
	// ExtKeyUsageMicrosoftServerGatedCrypto represents an EKU of MicrosoftServerGatedCrypto (oid: 1.3.6.1.4.1.311.10.3.3)
	ExtKeyUsageMicrosoftServerGatedCrypto = ExtKeyUsage(x509.ExtKeyUsageMicrosoftServerGatedCrypto)
	// ExtKeyUsageNetscapeServerGatedCrypto represents an EKU of NetscapeServerGatedCrypto (oid: 2.16.840.1.113730.4.1)
	ExtKeyUsageNetscapeServerGatedCrypto = ExtKeyUsage(x509.ExtKeyUsageNetscapeServerGatedCrypto)
	// ExtKeyUsageMicrosoftCommercialCodeSigning represents an EKU of MicrosoftCommercialCodeSigning (oid: 1.3.6.1.4.1.311.2.1.22)
	ExtKeyUsageMicrosoftCommercialCodeSigning = ExtKeyUsage(x509.ExtKeyUsageMicrosoftCommercialCodeSigning)
	// ExtKeyUsageMicrosoftKernelCodeSigning represents an EKU of MicrosoftKernelCodeSigning (oid: 1.3.6.1.4.1.311.61.1.1)
	ExtKeyUsageMicrosoftKernelCodeSigning = ExtKeyUsage(x509.ExtKeyUsageMicrosoftKernelCodeSigning)
)

var (
	// The ASN1 Object Identifier for the X509 extension Extended Key Usage. In ASN1
	// the specifiec Extended Key Usage OIDs are elements sequenced under this OID.
	ExtensionExtKeyUsageOid = asn1.ObjectIdentifier{2, 5, 29, 37}

	// The ASN1 Object Identifier for Extended Key Usage: Any
	ExtKeyUsageAnyOid = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	// The ASN1 Object Identifier for Extended Key Usage: ServerAuth
	ExtKeyUsageServerAuthOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	// The ASN1 Object Identifier for Extended Key Usage: ClientAuth
	ExtKeyUsageClientAuthOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	// The ASN1 Object Identifier for Extended Key Usage: CodeSigning
	ExtKeyUsageCodeSigningOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	// The ASN1 Object Identifier for Extended Key Usage: EmailProtection
	ExtKeyUsageEmailProtectionOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	// The ASN1 Object Identifier for Extended Key Usage: IPSECEndSystem
	ExtKeyUsageIPSECEndSystemOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	// The ASN1 Object Identifier for Extended Key Usage: IPSECTunnel
	ExtKeyUsageIPSECTunnelOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	// The ASN1 Object Identifier for Extended Key Usage: IPSECUser
	ExtKeyUsageIPSECUserOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	// The ASN1 Object Identifier for Extended Key Usage: TimeStamping
	ExtKeyUsageTimeStampingOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	// The ASN1 Object Identifier for Extended Key Usage: OCSPSigning
	ExtKeyUsageOCSPSigningOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	// The ASN1 Object Identifier for Extended Key Usage: MicrosoftServerGatedCrypto
	ExtKeyUsageMicrosoftServerGatedCryptoOid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	// The ASN1 Object Identifier for Extended Key Usage: MicrosoftCommercialCodeSigning
	ExtKeyUsageMicrosoftCommercialCodeSigningOid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	// The ASN1 Object Identifier for Extended Key Usage: MicrosoftKernelCodeSigning
	ExtKeyUsageMicrosoftKernelCodeSigningOid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
	// The ASN1 Object Identifier for Extended Key Usage: NetscapeServerGatedCrypto
	ExtKeyUsageNetscapeServerGatedCryptoOid = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
)

// Returns the string representation of this object
func (eku *ExtKeyUsage) String() string {
	switch *eku {
	case ExtKeyUsageAny:
		return strExtKeyUsageAny
	case ExtKeyUsageServerAuth:
		return strExtKeyUsageServerAuth
	case ExtKeyUsageClientAuth:
		return strExtKeyUsageClientAuth
	case ExtKeyUsageCodeSigning:
		return strExtKeyUsageCodeSigning
	case ExtKeyUsageEmailProtection:
		return strExtKeyUsageEmailProtection
	case ExtKeyUsageIPSECEndSystem:
		return strExtKeyUsageIPSECEndSystem
	case ExtKeyUsageIPSECTunnel:
		return strExtKeyUsageIPSECTunnel
	case ExtKeyUsageIPSECUser:
		return strExtKeyUsageIPSECUser
	case ExtKeyUsageTimeStamping:
		return strExtKeyUsageTimeStamping
	case ExtKeyUsageOCSPSigning:
		return strExtKeyUsageOCSPSigning
	case ExtKeyUsageMicrosoftServerGatedCrypto:
		return strExtKeyUsageMicrosoftServerGatedCrypto
	case ExtKeyUsageNetscapeServerGatedCrypto:
		return strExtKeyUsageNetscapeServerGatedCrypto
	case ExtKeyUsageMicrosoftCommercialCodeSigning:
		return strExtKeyUsageMicrosoftCommercialCodeSigning
	case ExtKeyUsageMicrosoftKernelCodeSigning:
		return strExtKeyUsageMicrosoftKernelCodeSigning
	default:
		return strUnknownExtKeyUsage
	}
}

// Returns the ASN1 Obect Indentifier represented by the ExtKeyUsage type
func (eku *ExtKeyUsage) Oid() (asn1.ObjectIdentifier, error) {
	switch *eku {
	case ExtKeyUsageAny:
		return ExtKeyUsageAnyOid, nil
	case ExtKeyUsageServerAuth:
		return ExtKeyUsageServerAuthOid, nil
	case ExtKeyUsageClientAuth:
		return ExtKeyUsageClientAuthOid, nil
	case ExtKeyUsageCodeSigning:
		return ExtKeyUsageCodeSigningOid, nil
	case ExtKeyUsageEmailProtection:
		return ExtKeyUsageEmailProtectionOid, nil
	case ExtKeyUsageIPSECEndSystem:
		return ExtKeyUsageIPSECEndSystemOid, nil
	case ExtKeyUsageIPSECTunnel:
		return ExtKeyUsageIPSECTunnelOid, nil
	case ExtKeyUsageIPSECUser:
		return ExtKeyUsageIPSECUserOid, nil
	case ExtKeyUsageTimeStamping:
		return ExtKeyUsageTimeStampingOid, nil
	case ExtKeyUsageOCSPSigning:
		return ExtKeyUsageOCSPSigningOid, nil
	case ExtKeyUsageMicrosoftServerGatedCrypto:
		return ExtKeyUsageMicrosoftServerGatedCryptoOid, nil
	case ExtKeyUsageNetscapeServerGatedCrypto:
		return ExtKeyUsageNetscapeServerGatedCryptoOid, nil
	case ExtKeyUsageMicrosoftCommercialCodeSigning:
		return ExtKeyUsageMicrosoftCommercialCodeSigningOid, nil
	case ExtKeyUsageMicrosoftKernelCodeSigning:
		return ExtKeyUsageMicrosoftKernelCodeSigningOid, nil
	default:
		return nil, fmt.Errorf("%w: %s", verror.VcertError, strUnknownExtKeyUsage)
	}
}

// X509Type() returns the crypto/x509.ExtKeyUsage type
func (eku *ExtKeyUsage) X509Type() x509.ExtKeyUsage {
	// This is essentially a cast to ExtKeyUsage type, since ExtKeyUsage is
	// an extension of crypt/x509.ExtKeyUsage
	return x509.ExtKeyUsage(*eku)
}

// Sets the ExtKeyUsage type via a string. Sets the object to UnknownExtKeyUsage if not
// one of the defined Extended Key Usage strings
func (eku *ExtKeyUsage) set(s string) {
	switch strings.ToUpper(s) {
	case strings.ToUpper(strExtKeyUsageAny):
		*eku = ExtKeyUsageAny
		return
	case strings.ToUpper(strExtKeyUsageServerAuth):
		*eku = ExtKeyUsageServerAuth
		return
	case strings.ToUpper(strExtKeyUsageClientAuth):
		*eku = ExtKeyUsageClientAuth
		return
	case strings.ToUpper(strExtKeyUsageCodeSigning):
		*eku = ExtKeyUsageCodeSigning
		return
	case strings.ToUpper(strExtKeyUsageEmailProtection):
		*eku = ExtKeyUsageEmailProtection
		return
	case strings.ToUpper(strExtKeyUsageIPSECEndSystem):
		*eku = ExtKeyUsageIPSECEndSystem
		return
	case strings.ToUpper(strExtKeyUsageIPSECTunnel):
		*eku = ExtKeyUsageIPSECTunnel
		return
	case strings.ToUpper(strExtKeyUsageIPSECUser):
		*eku = ExtKeyUsageIPSECUser
		return
	case strings.ToUpper(strExtKeyUsageTimeStamping):
		*eku = ExtKeyUsageTimeStamping
		return
	case strings.ToUpper(strExtKeyUsageOCSPSigning):
		*eku = ExtKeyUsageOCSPSigning
		return
	case strings.ToUpper(strExtKeyUsageMicrosoftServerGatedCrypto):
		*eku = ExtKeyUsageMicrosoftServerGatedCrypto
		return
	case strings.ToUpper(strExtKeyUsageNetscapeServerGatedCrypto):
		*eku = ExtKeyUsageNetscapeServerGatedCrypto
		return
	case strings.ToUpper(strExtKeyUsageMicrosoftCommercialCodeSigning):
		*eku = ExtKeyUsageMicrosoftCommercialCodeSigning
		return
	case strings.ToUpper(strExtKeyUsageMicrosoftKernelCodeSigning):
		*eku = ExtKeyUsageMicrosoftKernelCodeSigning
		return
	default:
		*eku = UnknownExtKeyUsage
		return
	}
}

func ParseExtKeyUsage(s string) (ExtKeyUsage, error) {
	eku := *new(ExtKeyUsage)
	eku.set(s)
	if eku == UnknownExtKeyUsage {
		return eku, fmt.Errorf("%w: %s \"%s\"", verror.VcertError, strUnknownExtKeyUsage, s)
	}
	return eku, nil
}

func addExtKeyUsage(req *x509.CertificateRequest, ekus []ExtKeyUsage) error {
	var oidToAdd []asn1.ObjectIdentifier
	for _, eku := range ekus {
		oid, _ := eku.Oid()
		if oid != nil {
			oidToAdd = append(oidToAdd, oid)
		}
	}

	if oidToAdd == nil && len(oidToAdd) < 1 {
		// There was nothing to add (unknown or empty ekus)
		return nil
	}

	bValue, err := asn1.Marshal(oidToAdd)
	if err != nil {
		return err
	}

	updatedExts := []pkix.Extension{
		{
			Id:       ExtensionExtKeyUsageOid,
			Critical: false,
			Value:    bValue,
		},
	}

	// Preserve any other extra extensions, if any
	for _, ext := range req.ExtraExtensions {
		if !ext.Id.Equal(ExtensionExtKeyUsageOid) {
			updatedExts = append(updatedExts, ext)
		}
	}
	req.ExtraExtensions = updatedExts
	return nil
}

// MarshalYAML customizes the behavior of ExtKeyUsage when being marshaled into a YAML document.
// The returned value is marshaled in place of the original value implementing Marshaller
func (eku *ExtKeyUsage) MarshalYAML() (interface{}, error) {
	return eku.String(), nil
}

// UnmarshalYAML customizes the behavior when being unmarshalled from a YAML document
func (eku *ExtKeyUsage) UnmarshalYAML(value *yaml.Node) error {
	var strValue string
	err := value.Decode(&strValue)
	if err != nil {
		return err
	}

	*eku, err = ParseExtKeyUsage(strValue)
	if err != nil {
		return err
	}
	return nil
}

// A slice that contains multiple ExtKeyUsage types, with useful functions for
// adding and parsing the slice
type ExtKeyUsageSlice []ExtKeyUsage

func NewExtKeyUsageSlice(param any) *ExtKeyUsageSlice {
	switch v := param.(type) {
	case ExtKeyUsageSlice:
		// This is essentially a copy
		t := make([]ExtKeyUsage, len(v))
		_ = copy(t, []ExtKeyUsage(v))
		ret := ExtKeyUsageSlice(t)
		return &ret
	default:
		ret := new(ExtKeyUsageSlice)
		_ = ret.Add(param)
		return ret
	}
}

func (es *ExtKeyUsageSlice) String() string {
	var ret string
	for _, s := range *es {
		ret += fmt.Sprintf("%s\n", s.String())
	}
	return ret
}

func (es *ExtKeyUsageSlice) Exists(eku ExtKeyUsage) bool {
	for _, el := range *es {
		if el == eku {
			return true
		}
	}
	return false
}

func (es *ExtKeyUsageSlice) Add(param any) error {
	switch v := param.(type) {
	case ExtKeyUsage:
		return es.appendByEKU(v)
	case string:
		return es.appendByString(v)
	case []string:
		var errs []string
		for _, s := range v {
			err := es.appendByString(s)
			if err != nil {
				errs = append(errs, s)
			}
		}
		if errs != nil {
			return fmt.Errorf("invalid EKUs: %s", strings.Join(errs, "; "))
		}
		return nil
	default:
		return fmt.Errorf("cannot add from unknown type passed to Add function")
	}
}

func (es *ExtKeyUsageSlice) appendByString(value string) error {
	temp, _ := ParseExtKeyUsage(value)
	err := es.appendByEKU(temp)
	if err != nil {
		return err
	}
	return nil
}

func (es *ExtKeyUsageSlice) appendByEKU(eku ExtKeyUsage) error {
	if eku != UnknownExtKeyUsage {
		if !es.Exists(eku) {
			*es = append(*es, eku)
		}
		return nil
	}
	return fmt.Errorf("invalid EKU: %s", eku.String())
}
