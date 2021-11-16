package cloud

import (
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"net/http"
	"regexp"
)

func parseCertificateInfo(httpStatusCode int, httpStatus string, body []byte) (*managedCertificate, error) {
	switch httpStatusCode {
	case http.StatusOK:
		var res = &managedCertificate{}
		err := json.Unmarshal(body, res)
		if err != nil {
			return nil, fmt.Errorf("failed to parse search results: %s, body: %s", err, body)
		}
		return res, nil
	default:
		if body != nil {
			respErrors, err := parseResponseErrors(body)
			if err == nil {
				respError := fmt.Sprintf("unexpected status code on Venafi Cloud certificate search. Status: %s\n", httpStatus)
				for _, e := range respErrors {
					respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
				}
				return nil, fmt.Errorf(respError)
			}
		}
		return nil, fmt.Errorf("unexpected status code on Venafi Cloud certificate search. Status: %s", httpStatus)
	}
}

func parseDEKInfo(httpStatusCode int, httpStatus string, body []byte) (*EdgeEncryptionKey, error) {
	switch httpStatusCode {
	case http.StatusOK:
		var res = &EdgeEncryptionKey{}
		err := json.Unmarshal(body, res)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DEK info results: %s, body: %s", err, body)
		}
		return res, nil
	default:
		if body != nil {
			respErrors, err := parseResponseErrors(body)
			if err == nil {
				respError := fmt.Sprintf("unexpected status code on VaaS retrieving DEK's info. Status: %s\n", httpStatus)
				for _, e := range respErrors {
					respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
				}
				return nil, fmt.Errorf(respError)
			}
		}
		return nil, fmt.Errorf("unexpected status code on VaaS retrieving DEK's info. Status. Status: %s", httpStatus)
	}
}

func Load32KeyByte(keyBytes []byte) (*[32]byte, error) {
	key := new([32]byte)
	copy(key[:], keyBytes)
	return key, nil
}

func getCsrAttributes(c *Connector, req *certificate.Request) (*CsrAttributes, error) {
	zone := c.zone.zone
	policy, err := c.GetPolicyWithRegex(zone)

	if err != nil {
		return nil, err
	}

	csrAttr := CsrAttributes{}
	valid := false

	if req.Subject.CommonName != "" {
		if policy.Policy != nil {

			valid, err = isValueMatch([]string{req.Subject.CommonName}, policy.Policy.Domains)
			if err != nil {
				return nil, err
			}

			if !valid {
				return nil, fmt.Errorf("specified CN %s, doesn't match with policy's specified domains %+q", req.Subject.CommonName, policy.Policy.Domains)
			}
		}
		csrAttr.CommonName = &req.Subject.CommonName
	}

	if len(req.Subject.Organization) > 0 {
		if policy.Policy != nil && policy.Policy.Subject != nil {
			valid, err := isValueMatch(req.Subject.Organization, policy.Policy.Subject.Orgs)
			if err != nil {
				return nil, err
			}
			if !valid {
				return nil, fmt.Errorf("specified organization %s, doesn't match with policy's specified organization %+q", req.Subject.Organization, policy.Policy.Subject.Orgs)
			}
		}
		csrAttr.Organization = &req.Subject.Organization[0]

	} else if policy.Default != nil && policy.Default.Subject != nil && policy.Default.Subject.Org != nil {
		org := *(policy.Default.Subject.Org)
		csrAttr.Organization = &org
	}

	if len(req.Subject.OrganizationalUnit) > 0 {
		if policy.Policy != nil && policy.Policy.Subject != nil {
			valid, err := isValueMatch(req.Subject.OrganizationalUnit, policy.Policy.Subject.OrgUnits)
			if err != nil {
				return nil, err
			}
			if !valid {
				return nil, fmt.Errorf("specified org unit  %+q, doesn't match with policy's specified org unit %+q", req.Subject.OrganizationalUnit, policy.Policy.Subject.OrgUnits)
			}
		}
		csrAttr.OrganizationalUnits = req.Subject.OrganizationalUnit
	} else if policy.Default != nil && policy.Default.Subject != nil && policy.Default.Subject.OrgUnits != nil {
		ou := policy.Default.Subject.OrgUnits
		csrAttr.OrganizationalUnits = ou
	}

	if len(req.Subject.Locality) > 0 {

		if policy.Policy != nil && policy.Policy.Subject != nil {
			valid, err := isValueMatch(req.Subject.Locality, policy.Policy.Subject.Localities)
			if err != nil {
				return nil, err
			}
			if !valid {
				return nil, fmt.Errorf("specified locality %s, doesn't match with policy's specified localities %+q", req.Subject.Locality[0], policy.Policy.Subject.Localities)
			}
		}

		csrAttr.Locality = &req.Subject.Locality[0]
	} else if policy.Default != nil && policy.Default.Subject != nil && policy.Default.Subject.Locality != nil {
		locality := *(policy.Default.Subject.Locality)
		csrAttr.Locality = &locality
	}

	if len(req.Subject.Province) > 0 {

		if policy.Policy != nil && policy.Policy.Subject != nil {
			valid, err := isValueMatch(req.Subject.Province, policy.Policy.Subject.States)
			if err != nil {
				return nil, err
			}
			if !valid {
				return nil, fmt.Errorf("specified state %s, doesn't match with policy's specified states %+q", req.Subject.Province[0], policy.Policy.Subject.States)
			}
		}

		csrAttr.State = &req.Subject.Province[0]
	} else if policy.Default != nil && policy.Default.Subject != nil && policy.Default.Subject.State != nil {
		state := *(policy.Default.Subject.State)
		csrAttr.State = &state
	}

	if len(req.Subject.Country) > 0 {

		if policy.Policy != nil && policy.Policy.Subject != nil {
			valid, err := isValueMatch(req.Subject.Country, policy.Policy.Subject.Countries)
			if err != nil {
				return nil, err
			}
			if !valid {
				return nil, fmt.Errorf("specified country %s, doesn't match with policy's specified countries %+q", req.Subject.Country[0], policy.Policy.Subject.Countries)
			}
		}

		csrAttr.Country = &req.Subject.Country[0]
	} else if policy.Default != nil && policy.Default.Subject != nil && policy.Default.Subject.Country != nil {
		country := *(policy.Default.Subject.Country)
		csrAttr.Country = &country
	}

	if len(req.DNSNames) > 0 {
		sanByType := SubjectAlternativeNamesByType{}
		sanByType.DnsNames = req.DNSNames
		csrAttr.SubjectAlternativeNamesByType = &sanByType
	}

	return &csrAttr, nil
}

//receives a string regex and a string to test
func testRegex(toTest, regex string) (bool, error) {
	compiledRegex, err := regexp.Compile(regex)
	if err != nil {
		return false, err
	}
	return compiledRegex.MatchString(toTest), nil
}

func isValueMatch(toTest, regexString []string) (bool, error) {
	validCN := true
	var err error
	if len(regexString) > 0 {
		for _, value := range toTest {
			valid := false
			for _, regexVal := range regexString {
				valid, err = testRegex(value, regexVal)
				if err != nil {
					return false, err
				}
				if valid {
					break
				}
			}
			if !valid {
				validCN = false
				break
			}
		}
	} else {
		validCN = true
	}
	return validCN, nil
}
