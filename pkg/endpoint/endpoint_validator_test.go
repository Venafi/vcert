package endpoint

import (
	"crypto/x509/pkix"
	"github.com/Venafi/vcert/pkg/certificate"
	"testing"
)

var any = []string{`.*`}

type validationTestCase struct {
	request     certificate.Request
	policy      Policy
	shouldMatch bool
}

var cases = []validationTestCase{
	{certificate.Request{}, Policy{}, false},
	{
		certificate.Request{Subject: pkix.Name{CommonName: "test.example.com"}},
		Policy{SubjectCNRegexes: []string{`^.*\.example\.com$`}, SubjectORegexes: any, SubjectCRegexes: any, SubjectLRegexes: any, SubjectOURegexes: any, SubjectSTRegexes: any},
		true,
	}, {
		certificate.Request{Subject: pkix.Name{CommonName: "test.example.co"}},
		Policy{SubjectCNRegexes: []string{`^.*\.example\.com$`}, SubjectORegexes: any, SubjectCRegexes: any, SubjectLRegexes: any, SubjectOURegexes: any, SubjectSTRegexes: any},
		false,
	}, {
		certificate.Request{Subject: pkix.Name{CommonName: "test.example.com", Organization: []string{"Venafi"}}},
		Policy{SubjectCNRegexes: any, SubjectORegexes: []string{"^Venafi$", "^TestCo$"}, SubjectCRegexes: any, SubjectLRegexes: any, SubjectOURegexes: any, SubjectSTRegexes: any},
		true,
	}, {
		certificate.Request{Subject: pkix.Name{CommonName: "test.example.com", Organization: []string{"Venafi", "Mozilla"}}},
		Policy{SubjectCNRegexes: any, SubjectORegexes: []string{"^Venafi$", "TestCo"}, SubjectCRegexes: any, SubjectLRegexes: any, SubjectOURegexes: any, SubjectSTRegexes: any},
		false,
	},
}

const csr1 = `-----BEGIN CERTIFICATE REQUEST-----
MIIBozCCAQUCAQAwYDELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEZMBcGA1UEAwwQdGVz
dC5leGFtcGxlLmNvbTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAbtdVExau15v
ANJkE7j5QI7xhkOc/mBXowb9eN7Rbost2KMCQY/e+F47R9BceEhtPuKwg0Q+WyyI
bGYfJk6C5u4tAHIRJ98VFYff8eguXJv4dVO/G8Pqf52kZ0RXLjMGtrbPeg3a0RSs
Zb+GAcnE2DQvy1+872XZzk0it4JrbBQf0UB8oAAwCgYIKoZIzj0EAwQDgYsAMIGH
AkEMMYyO8iJcqmKlBtP2a893rfVwsTv99xHmv5+aNaG0WK+n59OQVGyyMvtR6O+y
iS8RUQh3qWhWsEZoxtdimLsoQAJCASFzdxe7UJ5V6KP3ae5ihe1pGAWyzz9TmNV3
S/BIZL9MgWjew2mxMHM0wkqxI0abmB4QxK/dQDgJL0z5WUdG6U0B
-----END CERTIFICATE REQUEST-----
`

var csrCases = []struct {
	csr         string
	policy      Policy
	shouldMatch bool
}{
	{
		csr:         csr1,
		policy:      Policy{SubjectCNRegexes: []string{`^.*\.example\.com$`}, SubjectORegexes: any, SubjectCRegexes: any, SubjectLRegexes: any, SubjectOURegexes: any, SubjectSTRegexes: any},
		shouldMatch: true,
	},
	{
		csr:         csr1,
		policy:      Policy{SubjectCNRegexes: []string{`^.*\.example\.co$`}, SubjectORegexes: any, SubjectCRegexes: any, SubjectLRegexes: any, SubjectOURegexes: any, SubjectSTRegexes: any},
		shouldMatch: false,
	},
}

func makeCases() {
	for _, c := range csrCases {
		r := certificate.Request{}
		err := r.SetCSR([]byte(c.csr))
		if err != nil {
			panic(err)
		}
		cases = append(cases, validationTestCase{request: r, policy: c.policy, shouldMatch: c.shouldMatch})

	}

}

func TestPolicy_ValidateCertificateRequest(t *testing.T) {
	makeCases()
	for i, c := range cases {
		err := c.policy.ValidateCertificateRequest(&c.request)
		if (err == nil) != c.shouldMatch {
			t.Fatalf("case %d failed: %v", i, err)
		}
	}
}
