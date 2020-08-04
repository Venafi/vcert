/*
 * Copyright 2020 Venafi, Inc.
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
	"log"
	"net"
	"net/url"
)

// userPrincipalName format for ASN.1
type userPrincipalName struct {
	Name string `asn1:"utf8"`
}

// otherName SAN value format for ASN.1
type otherName struct {
	OID   asn1.ObjectIdentifier
	Value userPrincipalName `asn1:"tag:0"`
}

var (
	oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidUserPrincipalName       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
)

const (
	nameTypeOther = 0
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

// Workaround for lack of User Principal Name SAN support in crypto/x509 package
func addUserPrincipalNameSANs(req *x509.CertificateRequest, upNames []string) {
	sanBytes, err := marshalSANs(req.DNSNames, req.EmailAddresses, req.IPAddresses, req.URIs, upNames)
	if err != nil {
		log.Fatal(err)
	}

	extSubjectAltName := pkix.Extension{
		Id:       oidExtensionSubjectAltName,
		Critical: false,
		Value:    sanBytes,
	}

	updatedExts := []pkix.Extension{extSubjectAltName}

	// Preserve any other extra extensions, if any
	for _, ext := range req.ExtraExtensions {
		if !ext.Id.Equal(oidExtensionSubjectAltName) {
			updatedExts = append(updatedExts, ext)
		}
	}
	req.ExtraExtensions = updatedExts

	// Clear the SAN request attributes to prevent the SAN extension from being clobbered when CSR is generated
	req.DNSNames = nil
	req.EmailAddresses = nil
	req.IPAddresses = nil
	req.URIs = nil
}

// Enhance crypto/x509 marshalSANs method to additionally support User Principal Name SANs
// Based on https://github.com/golang/go/blob/master/src/crypto/x509/x509.go#L1656-L1678
func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL, uPNames []string) (derBytes []byte, err error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip})
	}
	for _, uri := range uris {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: 2, Bytes: []byte(uri.String())})
	}
	for _, upn := range uPNames {
		var raw asn1.RawValue
		name, _ := asn1.Marshal(otherName{
			OID: oidUserPrincipalName,
			Value: userPrincipalName{
				Name: upn,
			},
		})
		_, err = asn1.Unmarshal(name, &raw)
		if err != nil {
			return nil, fmt.Errorf("could not parse otherName SAN: %v", err)
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeOther, Class: 2, IsCompound: true, Bytes: raw.Bytes})
	}

	return asn1.Marshal(rawValues)
}

// Since crypto/x509 package is not aware of UPN SANs, implement our own parsing method
func getUserPrincipalNameSANs(cert *x509.Certificate) (ret []string, err error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidExtensionSubjectAltName) {
			continue
		}

		var seq asn1.RawValue
		rest, err := asn1.Unmarshal(ext.Value, &seq)
		if err != nil {
			return nil, err
		} else if len(rest) != 0 {
			return nil, fmt.Errorf("unexpected trailing data after X.509 extension")
		}
		if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
			return nil, asn1.StructuralError{Msg: "bad ASN.1 sequence for SAN"}
		}

		rest = seq.Bytes
		for len(rest) > 0 {
			var v asn1.RawValue
			rest, err = asn1.Unmarshal(rest, &v)
			if err != nil {
				return nil, err
			}

			upn, err := parseUserPrincipalNameSAN(v.Tag, v.FullBytes)
			if err != nil {
				return nil, err
			}
			if upn != "" {
				ret = append(ret, upn)
			}
		}
	}

	return ret, nil
}

func parseUserPrincipalNameSAN(tag int, data []byte) (name string, err error) {
	if tag != 0 {
		return "", nil // SAN is not an otherName
	}

	var other otherName
	_, err = asn1.UnmarshalWithParams(data, &other, "tag:0")
	if err != nil {
		return "", fmt.Errorf("could not parse otherName SAN: %v", err)
	}
	if other.OID.Equal(oidUserPrincipalName) {
		return other.Value.Name, nil
	}
	return "", nil // otherName SAN is not a user principal name
}
